//! Groups handlers for updating and managing order book state in response to
//! events elsewhere in the local node or the network

use circuits::verify_singleprover_proof;

use crate::{
    api::orderbook_management::OrderBookManagementMessage,
    proof_generation::jobs::ValidCommitmentsBundle,
    state::{NetworkOrder, OrderIdentifier, RelayerState},
    types::SizedValidCommitments,
};

use super::{errors::GossipError, server::GossipProtocolExecutor};

impl GossipProtocolExecutor {
    /// Dispatches messages from the cluster regarding order book management
    pub(super) fn handle_order_book_management_message(
        message: OrderBookManagementMessage,
        global_state: &RelayerState,
    ) -> Result<(), GossipError> {
        match message {
            OrderBookManagementMessage::OrderReceived { order_id } => {
                Self::handle_new_order(order_id, global_state);
                Ok(())
            }
            OrderBookManagementMessage::OrderProofUpdated { order_id, proof } => {
                Self::handle_new_validity_proof(order_id, proof, global_state)
            }
        }
    }

    /// Handles a newly discovered order added to the book
    fn handle_new_order(order_id: OrderIdentifier, global_state: &RelayerState) {
        global_state.add_order(NetworkOrder::new(order_id, false /* local */))
    }

    /// Handles a new validity proof attached to an order
    ///
    /// TODO: We also need to sanity check the statement variables with the contract state,
    /// e.g. merkle root, nullifiers, etc.
    fn handle_new_validity_proof(
        order_id: OrderIdentifier,
        proof_bundle: ValidCommitmentsBundle,
        global_state: &RelayerState,
    ) -> Result<(), GossipError> {
        // Verify the proof
        let bundle_clone = proof_bundle.clone();
        verify_singleprover_proof::<SizedValidCommitments>(
            proof_bundle.statement,
            proof_bundle.commitment,
            proof_bundle.proof,
        )
        .map_err(|err| GossipError::ValidCommitmentVerification(err.to_string()))?;

        // Add the order to the book in the `Validated` state
        if !global_state.read_order_book().contains_order(&order_id) {
            global_state.add_order(NetworkOrder::new(order_id, false /* local */));
        }

        global_state
            .read_order_book()
            .update_order_validity_proof(&order_id, bundle_clone);

        println!("Finished new validity proof");

        Ok(())
    }
}
