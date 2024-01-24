//! State interface for the order book

use common::types::{
    network_order::NetworkOrder,
    proof_bundles::{OrderValidityProofBundle, OrderValidityWitnessBundle},
    wallet::OrderIdentifier,
};

use crate::{error::StateError, notifications::ProposalWaiter, State, StateTransition};

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
        Ok(tx.get_order_info(order_id)?)
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
}

#[cfg(test)]
mod test {
    use common::types::{
        network_order::{test_helpers::dummy_network_order, NetworkOrderState},
        proof_bundles::mocks::dummy_validity_proof_bundle,
    };

    use crate::interface::test_helpers::mock_state;

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
