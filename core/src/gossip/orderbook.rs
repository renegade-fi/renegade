//! Groups handlers for updating and managing order book state in response to
//! events elsewhere in the local node or the network

use circuits::verify_singleprover_proof;
use libp2p::request_response::ResponseChannel;

use crate::{
    api::{
        gossip::{AuthenticatedGossipResponse, GossipOutbound, GossipResponse},
        orderbook_management::OrderInfoResponse,
    },
    proof_generation::jobs::ValidCommitmentsBundle,
    state::{NetworkOrder, OrderIdentifier},
    types::SizedValidCommitments,
};

use super::{
    errors::GossipError, jobs::OrderBookManagementJob, server::GossipProtocolExecutor,
    types::ClusterId,
};

impl GossipProtocolExecutor {
    /// Dispatches messages from the cluster regarding order book management
    pub(super) fn handle_order_book_management_job(
        &self,
        message: OrderBookManagementJob,
    ) -> Result<(), GossipError> {
        match message {
            OrderBookManagementJob::OrderInfo {
                order_id,
                response_channel,
            } => self.handle_order_info_request(order_id, response_channel),

            OrderBookManagementJob::OrderInfoResponse { info, .. } => {
                if let Some(order_info) = info {
                    self.handle_order_info_response(order_info)?;
                }

                Ok(())
            }

            OrderBookManagementJob::OrderReceived { order_id, cluster } => {
                self.handle_new_order(order_id, cluster);
                Ok(())
            }

            OrderBookManagementJob::OrderProofUpdated {
                order_id,
                cluster,
                proof,
            } => self.handle_new_validity_proof(order_id, cluster, proof),
        }
    }

    /// Handles a request for order information from a peer
    fn handle_order_info_request(
        &self,
        order_id: OrderIdentifier,
        response_channel: ResponseChannel<AuthenticatedGossipResponse>,
    ) -> Result<(), GossipError> {
        let order_info = self
            .global_state
            .read_order_book()
            .get_order_info(&order_id);

        self.network_channel
            .send(GossipOutbound::Response {
                channel: response_channel,
                message: GossipResponse::OrderInfo(OrderInfoResponse {
                    order_id,
                    info: order_info,
                }),
            })
            .map_err(|err| GossipError::SendMessage(err.to_string()))?;

        Ok(())
    }

    /// Handles a response to a request for order info
    fn handle_order_info_response(&self, mut order_info: NetworkOrder) -> Result<(), GossipError> {
        // If there is a proof attached to the order, verify it
        if let Some(proof_bundle) = order_info.valid_commit_proof.clone() {
            verify_singleprover_proof::<SizedValidCommitments>(
                proof_bundle.statement,
                proof_bundle.commitment,
                proof_bundle.proof,
            )
            .map_err(|err| GossipError::ValidCommitmentVerification(err.to_string()))?;
        }

        order_info.local = order_info.cluster == self.global_state.local_cluster_id;
        self.global_state.add_order(order_info);
        Ok(())
    }

    /// Handles a newly discovered order added to the book
    fn handle_new_order(&self, order_id: OrderIdentifier, cluster: ClusterId) {
        let is_local = cluster == self.global_state.local_cluster_id;
        self.global_state
            .add_order(NetworkOrder::new(order_id, cluster, is_local))
    }

    /// Handles a new validity proof attached to an order
    ///
    /// TODO: We also need to sanity check the statement variables with the contract state,
    /// e.g. merkle root, nullifiers, etc.
    fn handle_new_validity_proof(
        &self,
        order_id: OrderIdentifier,
        cluster: ClusterId,
        proof_bundle: ValidCommitmentsBundle,
    ) -> Result<(), GossipError> {
        let is_local = cluster.eq(&self.global_state.local_cluster_id);

        // Verify the proof
        if !is_local {
            let bundle_clone = proof_bundle.clone();
            verify_singleprover_proof::<SizedValidCommitments>(
                bundle_clone.statement,
                bundle_clone.commitment,
                bundle_clone.proof,
            )
            .map_err(|err| GossipError::ValidCommitmentVerification(err.to_string()))?;
        }

        // Add the order to the book in the `Validated` state
        if !self
            .global_state
            .read_order_book()
            .contains_order(&order_id)
        {
            self.global_state
                .add_order(NetworkOrder::new(order_id, cluster, is_local));
        }

        self.global_state
            .read_order_book()
            .update_order_validity_proof(&order_id, proof_bundle);

        Ok(())
    }
}
