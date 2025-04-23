//! State interface for the order book
//!
//! Order book setters do not need to go through raft consensus, so they are set
//! directly via this interface. This is because the order book interface is one
//! of unconditional writes only and inconsistent state is okay between cluster
//! peers

use circuit_types::{wallet::Nullifier, Amount};
use common::types::{
    gossip::WrappedPeerId,
    network_order::NetworkOrder,
    proof_bundles::{OrderValidityProofBundle, OrderValidityWitnessBundle},
    wallet::{OrderIdentifier, Pair},
    MatchingPoolName,
};
use constants::ORDER_STATE_CHANGE_TOPIC;
use external_api::bus_message::SystemBusMessage;
use libmdbx::TransactionKind;
use rand::{
    distributions::{Distribution, WeightedIndex},
    seq::SliceRandom,
    thread_rng,
};
use tracing::instrument;
use util::{res_some, telemetry::helpers::backfill_trace_field};

use crate::{
    caching::order_cache::OrderBookFilter,
    error::StateError,
    notifications::ProposalWaiter,
    storage::{error::StorageError, tx::StateTxn},
    StateInner, StateTransition,
};

/// The error message emitted when a caller attempts to add a local order
/// directly
const ERR_LOCAL_ORDER: &str = "local order should be updated through a wallet update";

impl StateInner {
    // -----------
    // | Getters |
    // -----------

    /// Returns whether or not the state contains a given order
    pub async fn contains_order(&self, order_id: &OrderIdentifier) -> Result<bool, StateError> {
        let oid = *order_id;
        self.with_read_tx(move |tx| {
            let contains = tx.contains_order(&oid)?;
            Ok(contains)
        })
        .await
    }

    /// Get an order
    pub async fn get_order(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<Option<NetworkOrder>, StateError> {
        let oid = *order_id;
        self.with_read_tx(move |tx| {
            let info = tx.get_order_info(&oid)?;
            Ok(info)
        })
        .await
    }

    /// Get a batch of orders
    ///
    /// Returns `None` for the orders that are not in the state
    pub async fn get_orders_batch(
        &self,
        order_ids: &[OrderIdentifier],
    ) -> Result<Vec<Option<NetworkOrder>>, StateError> {
        let order_ids = order_ids.to_vec();
        self.with_read_tx(move |tx| {
            let mut orders = Vec::with_capacity(order_ids.len());
            for id in order_ids.iter() {
                orders.push(tx.get_order_info(id)?);
            }
            Ok(orders)
        })
        .await
    }

    /// Get the nullifier for an order
    pub async fn get_nullifier_for_order(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<Option<Nullifier>, StateError> {
        let oid = *order_id;
        self.with_read_tx(move |tx| {
            let order = tx.get_order_info(&oid)?;
            Ok(order.map(|o| o.public_share_nullifier))
        })
        .await
    }

    /// Get the validity proofs for an order
    pub async fn get_validity_proofs(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<Option<OrderValidityProofBundle>, StateError> {
        let oid = *order_id;
        self.with_read_tx(move |tx| {
            let order = tx.get_order_info(&oid)?;
            Ok(order.and_then(|o| o.validity_proofs))
        })
        .await
    }

    /// Get the validity proof witness for an order
    pub async fn get_validity_proof_witness(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<Option<OrderValidityWitnessBundle>, StateError> {
        let oid = *order_id;
        self.with_read_tx(move |tx| {
            let order = tx.get_order_info(&oid)?;
            Ok(order.and_then(|o| o.validity_proof_witnesses))
        })
        .await
    }

    /// Return whether the given order is ready for a match
    pub async fn order_ready_for_match(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<bool, StateError> {
        let oid = *order_id;
        self.with_read_tx(move |tx| {
            let info = tx.get_order_info(&oid)?.ok_or(StateError::Db(StorageError::NotFound(
                format!("order {oid} not found in state"),
            )))?;
            Ok(info.ready_for_match())
        })
        .await
    }

    /// Get all known orders in the book
    ///
    /// Warning: this can be very slow when the state has a medium to large
    /// number of orders
    pub async fn get_all_orders(&self) -> Result<Vec<NetworkOrder>, StateError> {
        self.with_read_tx(move |tx| {
            let orders = tx.get_all_orders()?;
            Ok(orders)
        })
        .await
    }

    /// Get the matchable amount for both sides of a pair
    ///
    /// Returns (buy_amount, sell_amount)
    pub async fn get_liquidity_for_pair(&self, pair: &Pair) -> (Amount, Amount) {
        self.order_cache.get_matchable_amount(pair).await
    }

    // --- Heartbeat --- //

    /// Given a list of order IDs, return the subset that are not in the state
    pub async fn get_missing_orders(
        &self,
        order_ids: &[OrderIdentifier],
    ) -> Result<Vec<OrderIdentifier>, StateError> {
        let oids = order_ids.to_vec();
        self.with_read_tx(move |tx| {
            let mut missing = Vec::new();
            for id in oids.iter() {
                if !tx.contains_order(id)? {
                    missing.push(*id);
                }
            }
            Ok(missing)
        })
        .await
    }

    // --- Match --- //

    /// Sample a peer in the cluster managing an order
    pub async fn get_peer_managing_order(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<Option<WrappedPeerId>, StateError> {
        let oid = *order_id;
        self.with_read_tx(move |tx| {
            let order = res_some!(tx.get_order_info(&oid)?);
            let peers = tx.get_cluster_peers(&order.cluster)?;
            Ok(peers.choose(&mut thread_rng()).cloned())
        })
        .await
    }

    /// Get a list of matchable orders matching the given filter
    ///
    /// If `requires_serial` is true, then the returned orders will all be
    /// serial-preemptable, otherwise they only require concurrent preemption
    #[instrument(name = "get_matchable_orders", skip_all, fields(filter = ?filter, num_candidates, num_available))]
    pub async fn get_matchable_orders(
        &self,
        filter: OrderBookFilter,
    ) -> Result<Vec<OrderIdentifier>, StateError> {
        let candidates = self.order_cache.get_orders(filter).await;
        backfill_trace_field("num_candidates", candidates.len());
        let filtered = self.filter_matchable_orders(candidates, None /* matching_pool */).await?;
        backfill_trace_field("num_available", filtered.len());

        Ok(filtered)
    }

    /// Get a list of order IDs that are locally managed and ready for match
    #[instrument(name = "get_locally_matchable_orders", skip_all)]
    pub async fn get_all_matchable_orders(&self) -> Result<Vec<OrderIdentifier>, StateError> {
        let candidates = self.order_cache.get_all_orders().await;
        self.filter_matchable_orders(candidates, None /* matching_pool */).await
    }

    /// Get a list of order IDs that are locally managed and ready for match in
    /// the given matching pool
    #[instrument(name = "get_matchable_orders_in_matching_pool", skip_all, fields(matching_pool = ?matching_pool, num_candidates, num_available))]
    pub async fn get_matchable_orders_in_matching_pool(
        &self,
        matching_pool: MatchingPoolName,
        filter: OrderBookFilter,
    ) -> Result<Vec<OrderIdentifier>, StateError> {
        let candidates = self.order_cache.get_orders(filter).await;
        backfill_trace_field("num_candidates", candidates.len());
        let filtered = self.filter_matchable_orders(candidates, Some(matching_pool)).await?;
        backfill_trace_field("num_available", filtered.len());

        Ok(filtered)
    }

    /// Get all order IDs in a given matching pool
    #[instrument(name = "get_all_orders_in_matching_pool", skip_all, fields(matching_pool = ?matching_pool))]
    pub async fn get_all_orders_in_matching_pool(
        &self,
        matching_pool: MatchingPoolName,
    ) -> Result<Vec<OrderIdentifier>, StateError> {
        let candidates = self.order_cache.get_all_orders().await;
        self.filter_matchable_orders(candidates, Some(matching_pool)).await
    }

    /// Filter a set of matchable orders candidates
    ///
    /// Provides two checks:
    /// - Filters out orders with non-empty task queues
    /// - Filters out orders in incorrect matching pools
    async fn filter_matchable_orders(
        &self,
        orders: Vec<OrderIdentifier>,
        matching_pool: Option<MatchingPoolName>,
    ) -> Result<Vec<OrderIdentifier>, StateError> {
        self.with_read_tx(move |tx| {
            let mut res = Vec::new();
            for id in orders.into_iter() {
                if let Some(ref pool) = matching_pool {
                    let order_matching_pool = tx.get_matching_pool_for_order(&id)?;
                    if order_matching_pool != *pool {
                        continue;
                    }
                }

                // Check if the task queue for the order is free
                if Self::is_serial_queue_free(&id, tx)? {
                    res.push(id);
                }
            }
            Ok(res)
        })
        .await
    }

    /// Choose an order to handshake with according to their priorities
    ///
    /// TODO(@joeykraut): Optimize this method when implementing multi-cluster
    pub async fn choose_handshake_order(&self) -> Result<Option<OrderIdentifier>, StateError> {
        self.with_read_tx(|tx| {
            // Get all orders and filter by those that are not managed internally and ready
            // for match
            let mut all_orders = tx.get_all_orders()?;

            let my_cluster = tx.get_cluster_id()?;
            all_orders.retain(|o| o.cluster != my_cluster && o.ready_for_match());

            // Get the priorities of each order
            let mut priorities = Vec::with_capacity(all_orders.len());
            for order in all_orders.iter().map(|o| o.id) {
                let priority = tx.get_order_priority(&order)?;
                priorities.push(priority.get_effective_priority());
            }

            // Sample a random priority-weighted order from the result
            if priorities.is_empty() {
                return Ok(None);
            }

            let mut rng = thread_rng();
            let distribution = WeightedIndex::new(&priorities).unwrap();
            let sampled = all_orders.get(distribution.sample(&mut rng)).unwrap();

            Ok(Some(sampled.id))
        })
        .await
    }

    // -----------
    // | Setters |
    // -----------

    /// Add an order to the book
    pub async fn add_order(&self, mut order: NetworkOrder) -> Result<(), StateError> {
        self.with_write_tx(move |tx| {
            // Local orders should be added to the state through a wallet update written to
            // the raft log
            let cluster_id = tx.get_cluster_id()?;
            let is_local = order.cluster == cluster_id;
            if is_local {
                return Err(StateError::InvalidUpdate(ERR_LOCAL_ORDER.to_string()));
            }

            // Add the local order to the state
            order.local = false;
            tx.write_order_priority(&order)?;
            tx.write_order(&order)?;

            Ok(())
        })
        .await
    }

    /// Add a validity proof to an order
    pub async fn add_order_validity_proof(
        &self,
        order_id: OrderIdentifier,
        proof: OrderValidityProofBundle,
    ) -> Result<(), StateError> {
        let bus = self.bus.clone();
        self.with_write_tx(move |tx| {
            tx.attach_validity_proof(&order_id, proof)?;

            // Read back the order and check if it is local, if so, abort
            let order = tx.get_order_info(&order_id)?.unwrap();
            if order.local {
                return Err(StateError::InvalidUpdate(ERR_LOCAL_ORDER.to_string()));
            }

            // Push a notification to the system bus
            bus.publish(
                ORDER_STATE_CHANGE_TOPIC.to_string(),
                SystemBusMessage::OrderStateChange { order },
            );
            Ok(())
        })
        .await
    }

    /// Add a validity proof and witness to an order managed by the local node
    pub async fn add_local_order_validity_bundle(
        &self,
        order_id: OrderIdentifier,
        proof: OrderValidityProofBundle,
        witness: OrderValidityWitnessBundle,
    ) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::AddOrderValidityBundle { order_id, proof, witness })
            .await
    }

    /// Nullify all orders on the given nullifier
    pub async fn nullify_orders(&self, nullifier: Nullifier) -> Result<(), StateError> {
        self.with_write_tx(move |tx| {
            tx.nullify_orders(nullifier)?;
            Ok(())
        })
        .await
    }
}

// -----------
// | Helpers |
// -----------

impl StateInner {
    /// Checks whether a given serial task queue is free, for a given order
    fn is_serial_queue_free<T: TransactionKind>(
        order_id: &OrderIdentifier,
        tx: &StateTxn<T>,
    ) -> Result<bool, StateError> {
        // Check that there are no tasks in the queue for the containing wallet
        // This avoids unnecessary preemptions or possible dropped matches
        //
        // Note that we only check for serial tasks here, concurrent tasks
        // will be preempted by the task queue
        let wallet_id = match tx.get_wallet_id_for_order(order_id)? {
            None => return Ok(false),
            Some(wallet) => wallet,
        };

        let queue_locked_serial = !tx.serial_tasks_active(&wallet_id)?;
        Ok(queue_locked_serial)
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    use common::types::{
        network_order::{test_helpers::dummy_network_order, NetworkOrderState},
        proof_bundles::mocks::dummy_validity_proof_bundle,
    };

    use crate::test_helpers::mock_state;

    /// Test adding an order to the state
    #[tokio::test]
    async fn test_add_order() {
        let state = mock_state().await;

        let order = dummy_network_order();
        state.add_order(order.clone()).await.unwrap();

        // Check for the order in the state
        let stored_order = state.get_order(&order.id).await.unwrap();
        assert_eq!(stored_order, Some(order));
    }

    /// Tests the `get_orders_batch` method with missing orders
    #[tokio::test]
    async fn test_get_orders_batch() {
        let state = mock_state().await;

        // Create two orders and only add one
        let order1 = dummy_network_order();
        let order2 = dummy_network_order();

        state.add_order(order1.clone()).await.unwrap();

        // Get the orders in a batch call
        let res = state.get_orders_batch(&[order1.id, order2.id]).await.unwrap();
        assert_eq!(res.len(), 2);
        assert_eq!(res[0], Some(order1));
        assert_eq!(res[1], None);
    }

    /// Tests getting the missing orders
    #[tokio::test]
    async fn test_get_missing_orders() {
        let state = mock_state().await;

        // Create three orders and only add one
        let order1 = dummy_network_order();
        let order2 = dummy_network_order();
        let order3 = dummy_network_order();

        state.add_order(order1.clone()).await.unwrap();

        // Check for the order in the state
        let stored_order = state.get_order(&order1.id).await.unwrap();
        assert_eq!(stored_order.unwrap(), order1);

        // Get the missing orders
        let mut missing =
            state.get_missing_orders(&[order1.id, order2.id, order3.id]).await.unwrap();
        missing.sort();
        let mut expected = vec![order2.id, order3.id];
        expected.sort();

        assert_eq!(missing, expected);
    }

    /// Test adding a validity proof to an order
    #[tokio::test]
    async fn test_add_order_validity_proof() {
        let state = mock_state().await;

        let order = dummy_network_order();
        state.add_order(order.clone()).await.unwrap();

        // Check for the order in the state
        let stored_order = state.get_order(&order.id).await.unwrap();
        assert_eq!(stored_order, Some(order.clone()));

        // Add a validity proof to the order
        let proof = dummy_validity_proof_bundle();
        state.add_order_validity_proof(order.id, proof).await.unwrap();

        // Check for the order in the state
        let stored_order = state.get_order(&order.id).await.unwrap().unwrap();
        assert_eq!(stored_order.state, NetworkOrderState::Verified);
        assert!(stored_order.validity_proofs.is_some());
    }

    /// Tests nullifying an order
    #[tokio::test]
    async fn test_nullify_order() {
        let state = mock_state().await;

        let order = dummy_network_order();
        state.add_order(order.clone()).await.unwrap();

        // Check for the order in the state
        let stored_order = state.get_order(&order.id).await.unwrap();
        assert_eq!(stored_order, Some(order.clone()));

        // Nullify the order
        state.nullify_orders(order.public_share_nullifier).await.unwrap();

        // Check for the order in the state
        assert!(state.get_order(&order.id).await.unwrap().is_none());
    }
}
