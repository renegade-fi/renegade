//! State interface for the order book
//!
//! Order book setters do not need to go through raft consensus, so they are set
//! directly via this interface. This is because the order book interface is one
//! of unconditional writes only and inconsistent state is okay between cluster
//! peers

use circuit_types::{Amount, Nullifier};
use libmdbx::TransactionKind;
use rand::{
    Rng,
    distributions::{Distribution, WeightedIndex},
    thread_rng,
};
use tracing::instrument;
use types_account::{MatchingPoolName, OrderId, pair::Pair};
use types_gossip::{ClusterId, WrappedPeerId, network_order::NetworkOrder};
use util::{res_some, telemetry::helpers::backfill_trace_field};

use crate::{
    StateInner,
    caching::order_cache::OrderBookFilter,
    error::StateError,
    storage::{
        error::StorageError,
        traits::{RkyvValue, WithScalar},
        tx::StateTxn,
    },
};

/// The error message emitted when a caller attempts to add a local order
/// directly
const ERR_LOCAL_ORDER: &str = "local order should be updated through a wallet update";

impl StateInner {
    // -----------
    // | Getters |
    // -----------

    /// Returns whether or not the state contains a given order
    pub async fn contains_order(&self, order_id: &OrderId) -> Result<bool, StateError> {
        let oid = *order_id;
        self.with_read_tx(move |tx| {
            let contains = tx.contains_order(&oid)?;
            Ok(contains)
        })
        .await
    }

    /// Get an order
    pub async fn get_network_order(
        &self,
        order_id: &OrderId,
    ) -> Result<Option<NetworkOrder>, StateError> {
        let oid = *order_id;
        self.with_read_tx(move |tx| {
            let info_value = res_some!(tx.get_order_info(&oid)?);
            let info = info_value.deserialize()?;
            Ok(Some(info))
        })
        .await
    }

    /// Get a batch of orders
    ///
    /// Returns `None` for the orders that are not in the state
    pub async fn get_network_orders(
        &self,
        order_ids: &[OrderId],
    ) -> Result<Vec<NetworkOrder>, StateError> {
        let order_ids = order_ids.to_vec();
        self.with_read_tx(move |tx| {
            let mut orders = Vec::with_capacity(order_ids.len());
            for id in order_ids.iter() {
                if let Some(o) = tx.get_order_info(id)? {
                    orders.push(o.deserialize()?);
                }
            }

            Ok(orders)
        })
        .await
    }

    /// Get the nullifier for an order
    pub async fn get_nullifier_for_order(
        &self,
        order_id: &OrderId,
    ) -> Result<Option<Nullifier>, StateError> {
        let oid = *order_id;
        self.with_read_tx(move |tx| {
            let order = res_some!(tx.get_order_info(&oid)?);
            let nullifier = WithScalar::from_archived(&order.nullifier)?.into_inner();
            Ok(Some(nullifier))
        })
        .await
    }

    /// Return whether the given order is ready for a match
    pub async fn order_ready_for_match(&self, order_id: &OrderId) -> Result<bool, StateError> {
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
            let orders = tx
                .get_all_orders()?
                .into_iter()
                .map(|o| o.deserialize())
                .collect::<Result<Vec<_>, _>>()?;

            Ok(orders)
        })
        .await
    }

    /// Get the matchable amount for both sides of a pair
    ///
    /// Returns (buy_amount, sell_amount) where buy amount is denominated in the
    /// quote token, sell amount is denominated in the base token
    pub async fn get_liquidity_for_pair(&self, pair: &Pair) -> (Amount, Amount) {
        self.order_cache.get_matchable_amount(pair)
    }

    // --- Heartbeat --- //

    /// Given a list of order IDs, return the subset that are not in the state
    pub async fn get_missing_orders(
        &self,
        order_ids: &[OrderId],
    ) -> Result<Vec<OrderId>, StateError> {
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
        order_id: &OrderId,
    ) -> Result<Option<WrappedPeerId>, StateError> {
        let oid = *order_id;
        self.with_read_tx(move |tx| {
            // Get the cluster ID managing the order
            let order = res_some!(tx.get_order_info(&oid)?);
            let cluster = ClusterId::from_archived(&order.cluster)?;

            // Get the peers in the cluster
            let peers = res_some!(tx.get_cluster_peers(&cluster)?);
            let n_peers = peers.len();
            if n_peers == 0 {
                return Ok(None);
            }

            // Choose a random peer from the cluster
            let peer_idx = thread_rng().gen_range(0..n_peers);
            let peer = peers.iter().nth(peer_idx).unwrap(); // safe because bounds are sampled
            Ok(Some(WrappedPeerId::from_archived(peer)?))
        })
        .await
    }

    /// Get a list of matchable orders matching the given filter
    ///
    /// If `requires_serial` is true, then the returned orders will all be
    /// serial-preemptable, otherwise they only require concurrent preemption
    #[instrument(name = "get_matchable_orders", skip_all, fields(filter = ?filter, num_candidates, num_available))]
    pub fn get_matchable_orders(
        &self,
        filter: &OrderBookFilter,
    ) -> Result<Vec<OrderId>, StateError> {
        let candidates = self.order_cache.get_orders(filter);
        backfill_trace_field("num_candidates", candidates.len());
        let filtered = self.filter_matchable_orders(candidates, None /* matching_pool */)?;
        backfill_trace_field("num_available", filtered.len());

        Ok(filtered)
    }

    /// Get a list of order IDs that are locally managed and ready for match
    #[instrument(name = "get_locally_matchable_orders", skip_all)]
    pub fn get_all_matchable_orders(&self) -> Result<Vec<OrderId>, StateError> {
        let candidates = self.order_cache.get_all_orders();
        self.filter_matchable_orders(candidates, None /* matching_pool */)
    }

    /// Get a list of order IDs that are locally managed and ready for match in
    /// the given matching pool
    #[instrument(name = "get_matchable_orders_in_matching_pool", skip_all, fields(matching_pool = ?matching_pool, num_candidates, num_available))]
    pub fn get_matchable_orders_in_matching_pool(
        &self,
        matching_pool: MatchingPoolName,
        filter: &OrderBookFilter,
    ) -> Result<Vec<OrderId>, StateError> {
        let candidates = self.order_cache.get_orders(filter);
        backfill_trace_field("num_candidates", candidates.len());
        let filtered = self.filter_matchable_orders(candidates, Some(matching_pool))?;
        backfill_trace_field("num_available", filtered.len());

        Ok(filtered)
    }

    /// Get all order IDs in a given matching pool
    #[instrument(name = "get_all_orders_in_matching_pool", skip_all, fields(matching_pool = ?matching_pool))]
    pub async fn get_all_orders_in_matching_pool(
        &self,
        matching_pool: MatchingPoolName,
    ) -> Result<Vec<OrderId>, StateError> {
        let candidates = self.order_cache.get_all_orders();
        self.filter_matchable_orders(candidates, Some(matching_pool))
    }

    /// Filter a set of matchable orders candidates
    ///
    /// Provides two checks:
    /// - Filters out orders with non-empty task queues
    /// - Filters out orders in incorrect matching pools
    fn filter_matchable_orders(
        &self,
        orders: Vec<OrderId>,
        matching_pool: Option<MatchingPoolName>,
    ) -> Result<Vec<OrderId>, StateError> {
        self.with_blocking_read_tx(move |tx| {
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
    }

    /// Choose an order to handshake with according to their priorities
    ///
    /// TODO(@joeykraut): Optimize this method when implementing multi-cluster
    pub async fn choose_handshake_order(&self) -> Result<Option<OrderId>, StateError> {
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

    /// Nullify all orders on the given nullifier
    pub async fn nullify_orders(&self, nullifier: Nullifier) -> Result<(), StateError> {
        let order_id = self
            .with_write_tx(move |tx| {
                let order_id = tx.nullify_order(nullifier)?;
                Ok(order_id)
            })
            .await?;

        // Remove the orders from the order cache
        if let Some(order_id) = order_id {
            self.order_cache.remove_order(order_id);
        }

        Ok(())
    }
}

// -----------
// | Helpers |
// -----------

impl StateInner {
    /// Checks whether a given serial task queue is free, for a given order
    fn is_serial_queue_free<T: TransactionKind>(
        order_id: &OrderId,
        tx: &StateTxn<T>,
    ) -> Result<bool, StateError> {
        // Check that there are no tasks in the queue for the containing wallet
        // This avoids unnecessary preemptions or possible dropped matches
        //
        // Note that we only check for serial tasks here, concurrent tasks
        // will be preempted by the task queue
        let account_id = match tx.get_account_id_for_order(order_id)? {
            None => return Ok(false),
            Some(account_id) => account_id,
        };

        let queue_locked_serial = !tx.serial_tasks_active(&account_id)?;
        Ok(queue_locked_serial)
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {

    use types_gossip::network_order::test_helpers::dummy_network_order;

    use crate::test_helpers::mock_state;

    /// Test adding an order to the state
    #[tokio::test]
    async fn test_add_order() {
        let state = mock_state().await;

        let order = dummy_network_order();
        state.add_order(order.clone()).await.unwrap();

        // Check for the order in the state
        let stored_order = state.get_network_order(&order.id).await.unwrap();
        assert_eq!(stored_order, Some(order));
    }

    /// Tests the `get_orders_batch` method with missing orders
    #[tokio::test]
    async fn test_get_orders_batch() {
        let state = mock_state().await;

        // Create two orders
        let order1 = dummy_network_order();
        let order2 = dummy_network_order();
        state.add_order(order1.clone()).await.unwrap();
        state.add_order(order2.clone()).await.unwrap();

        // Get the orders in a batch call
        let res = state.get_network_orders(&[order1.id, order2.id]).await.unwrap();
        assert_eq!(res.len(), 2);

        assert_eq!(res[0], order1);
        assert_eq!(res[1], order2);
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
        let stored_order = state.get_network_order(&order1.id).await.unwrap();
        assert_eq!(stored_order.unwrap(), order1);

        // Get the missing orders
        let mut missing =
            state.get_missing_orders(&[order1.id, order2.id, order3.id]).await.unwrap();
        missing.sort();
        let mut expected = vec![order2.id, order3.id];
        expected.sort();

        assert_eq!(missing, expected);
    }

    /// Tests nullifying an order
    #[tokio::test]
    async fn test_nullify_order() {
        let state = mock_state().await;

        let order = dummy_network_order();
        state.add_order(order.clone()).await.unwrap();

        // Check for the order in the state
        let stored_order = state.get_network_order(&order.id).await.unwrap();
        assert_eq!(stored_order, Some(order.clone()));

        // Nullify the order
        state.nullify_orders(order.nullifier).await.unwrap();

        // Check for the order in the state
        assert!(state.get_network_order(&order.id).await.unwrap().is_none());
    }
}
