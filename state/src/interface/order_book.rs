//! State interface for the order book
//!
//! Order book setters do not need to go through raft consensus, so they are set
//! directly via this interface. This is because the order book interface is one
//! of unconditional writes only and inconsistent state is okay between cluster
//! peers

use circuit_types::wallet::Nullifier;
use common::types::{
    gossip::WrappedPeerId,
    network_order::NetworkOrder,
    proof_bundles::{OrderValidityProofBundle, OrderValidityWitnessBundle},
    wallet::OrderIdentifier,
};
use constants::ORDER_STATE_CHANGE_TOPIC;
use external_api::bus_message::SystemBusMessage;
use rand::{
    distributions::{Distribution, WeightedIndex},
    seq::SliceRandom,
    thread_rng,
};
use util::res_some;

use crate::{
    error::StateError, notifications::ProposalWaiter, storage::error::StorageError, State,
    StateTransition,
};

/// The error message emitted when a caller attempts to add a local order
/// directly
const ERR_LOCAL_ORDER: &str = "local order should be updated through a wallet update";

impl State {
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
    pub async fn get_all_orders(&self) -> Result<Vec<NetworkOrder>, StateError> {
        self.with_read_tx(move |tx| {
            let orders = tx.get_all_orders()?;
            Ok(orders)
        })
        .await
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

    /// Get a list of order IDs that are locally managed and ready for match
    ///
    /// TODO: Optimize this if necessary, possibly by caching this list
    pub async fn get_locally_matchable_orders(&self) -> Result<Vec<OrderIdentifier>, StateError> {
        self.with_read_tx(|tx| {
            // Get all the local orders
            let local_order_ids = tx.get_local_orders()?;

            let mut res = Vec::new();
            for id in local_order_ids.into_iter() {
                if let Some(info) = tx.get_order_info(&id)? {
                    // Check that there are no tasks in the queue for the containing wallet
                    // This avoids unnecessary preemptions or possible dropped matches
                    let wallet_id = match tx.get_wallet_for_order(&info.id)? {
                        None => continue,
                        Some(wallet) => wallet,
                    };

                    if !tx.is_queue_empty(&wallet_id)? || tx.is_queue_paused(&wallet_id)? {
                        continue;
                    }

                    // Check that the order itself is ready for a match
                    if info.ready_for_match() {
                        res.push(id);
                    }
                }
            }

            Ok(res)
        })
        .await
    }

    /// Choose an order to handshake with according to their priorities
    ///
    /// TODO: Optimize this method if necessary
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
            tx.update_order_nullifier_set(&order.id, order.public_share_nullifier)?;

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
