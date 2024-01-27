//! State interface for the order book

use circuit_types::wallet::Nullifier;
use common::types::{
    gossip::WrappedPeerId,
    network_order::NetworkOrder,
    proof_bundles::{OrderValidityProofBundle, OrderValidityWitnessBundle},
    wallet::OrderIdentifier,
};
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

impl State {
    // -----------
    // | Getters |
    // -----------

    /// Get an order
    pub fn get_order(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<Option<NetworkOrder>, StateError> {
        let tx = self.db.new_read_tx()?;
        let info = tx.get_order_info(order_id)?;
        tx.commit()?;

        Ok(info)
    }

    /// Get the nullifier for an order
    pub fn get_nullifier_for_order(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<Option<Nullifier>, StateError> {
        let order = self.get_order(order_id)?;
        Ok(order.map(|o| o.public_share_nullifier))
    }

    /// Get the validity proofs for an order
    pub fn get_validity_proofs(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<Option<OrderValidityProofBundle>, StateError> {
        let order = self.get_order(order_id)?;
        Ok(order.and_then(|o| o.validity_proofs))
    }

    /// Get the validity proof witness for an order
    pub fn get_validity_proof_witness(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<Option<OrderValidityWitnessBundle>, StateError> {
        let order = self.get_order(order_id)?;
        Ok(order.and_then(|o| o.validity_proof_witnesses))
    }

    /// Return whether the given order is ready for a match
    pub fn order_ready_for_match(&self, order_id: &OrderIdentifier) -> Result<bool, StateError> {
        let tx = self.db.new_read_tx()?;
        let info = tx.get_order_info(order_id)?.ok_or(StateError::Db(StorageError::NotFound(
            format!("order {order_id} not found in state"),
        )))?;
        tx.commit()?;

        Ok(info.ready_for_match())
    }

    /// Get all known orders in the book
    pub fn get_all_orders(&self) -> Result<Vec<NetworkOrder>, StateError> {
        let tx = self.db.new_read_tx()?;
        let orders = tx.get_all_orders()?;
        tx.commit()?;

        Ok(orders)
    }

    /// Sample a peer in the cluster managing an order
    pub fn get_peer_managing_order(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<Option<WrappedPeerId>, StateError> {
        let tx = self.db.new_read_tx()?;
        let order = res_some!(tx.get_order_info(order_id)?);
        let peers = tx.get_cluster_peers(&order.cluster)?;
        tx.commit()?;

        // Sample a peer
        let mut rng = thread_rng();
        let peer = peers.choose(&mut rng).cloned();
        Ok(peer)
    }

    /// Get a list of order IDs that are locally managed and ready for match
    ///
    /// TODO: Optimize this if necessary, possibly by caching this list
    pub fn get_locally_matchable_orders(&self) -> Result<Vec<OrderIdentifier>, StateError> {
        let tx = self.db.new_read_tx()?;

        // Get all the local orders
        let local_order_ids = tx.get_local_orders()?;

        let mut res = Vec::new();
        for id in local_order_ids.into_iter() {
            if let Some(info) = tx.get_order_info(&id)? {
                if info.ready_for_match() {
                    res.push(id);
                }
            }
        }

        tx.commit()?;
        Ok(res)
    }

    /// Choose an order to handshake with according to their priorities
    ///
    /// TODO: Optimize this method if necessary
    pub fn choose_handshake_order(&self) -> Result<Option<OrderIdentifier>, StateError> {
        let tx = self.db.new_read_tx()?;

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
        tx.commit()?;

        // Sample a random priority-weighted order from the result
        let mut rng = thread_rng();
        let distribution = WeightedIndex::new(&priorities).unwrap();
        let sampled = all_orders.get(distribution.sample(&mut rng)).unwrap();

        Ok(Some(sampled.id))
    }

    // -----------
    // | Setters |
    // -----------

    /// Add an order to the book
    pub fn add_order(&self, order: NetworkOrder) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::AddOrder { order })
    }

    /// Add a validity proof to an order
    pub fn add_order_validity_proof(
        &self,
        order_id: OrderIdentifier,
        proof: OrderValidityProofBundle,
        witness: Option<OrderValidityWitnessBundle>,
    ) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::AddOrderValidityProof { order_id, proof, witness })
    }

    /// Nullify all orders on the given nullifier
    pub fn nullify_orders(&self, nullifier: Nullifier) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::NullifyOrders { nullifier })
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
        let state = mock_state();

        let order = dummy_network_order();
        state.add_order(order.clone()).unwrap().await.unwrap();

        // Check for the order in the state
        let stored_order = state.get_order(&order.id).unwrap();
        assert_eq!(stored_order, Some(order));
    }

    /// Test adding a validity proof to an order
    #[tokio::test]
    async fn test_add_order_validity_proof() {
        let state = mock_state();

        let order = dummy_network_order();
        state.add_order(order.clone()).unwrap().await.unwrap();

        // Check for the order in the state
        let stored_order = state.get_order(&order.id).unwrap();
        assert_eq!(stored_order, Some(order.clone()));

        // Add a validity proof to the order
        let proof = dummy_validity_proof_bundle();
        state.add_order_validity_proof(order.id, proof, None /* witness */).unwrap().await.unwrap();

        // Check for the order in the state
        let stored_order = state.get_order(&order.id).unwrap().unwrap();
        assert_eq!(stored_order.state, NetworkOrderState::Verified);
        assert!(stored_order.validity_proofs.is_some());
    }
}
