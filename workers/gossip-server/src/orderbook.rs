//! Groups handlers for updating and managing order book state in response to
//! events elsewhere in the local node or the network

use circuit_types::wallet::Nullifier;
use circuits::{
    verify_singleprover_proof,
    zk_circuits::{
        proof_linking::validate_sized_commitments_reblind_link,
        valid_commitments::SizedValidCommitments, valid_reblind::SizedValidReblind,
    },
};
use common::types::{
    gossip::ClusterId,
    network_order::{NetworkOrder, NetworkOrderState},
    proof_bundles::OrderValidityProofBundle,
    wallet::OrderIdentifier,
};
use futures::executor::block_on;
use gossip_api::{
    pubsub::orderbook::OrderBookManagementMessage,
    request_response::{orderbook::OrderInfoResponse, GossipResponse},
};
use tracing::log;
use util::err_str;

use super::{errors::GossipError, server::GossipProtocolExecutor};

/// Error message emitted when an already-used nullifier is received
const ERR_NULLIFIER_USED: &str = "invalid nullifier, already used";
/// Error message emitted when a Merkle root is not found in the contract
/// history
const ERR_INVALID_MERKLE_ROOT: &str = "invalid merkle root, not in contract history";

impl GossipProtocolExecutor {
    // --------------------
    // | Inbound Requests |
    // --------------------

    /// Handles a request for order information from a peer
    pub(crate) fn handle_order_info_request(
        &self,
        order_ids: Vec<OrderIdentifier>,
    ) -> Result<GossipResponse, GossipError> {
        let info = self.global_state.get_orders_batch(&order_ids)?;
        let order_info = info.into_iter().flatten().collect();

        let resp = OrderInfoResponse { order_info };
        Ok(GossipResponse::OrderInfo(resp))
    }

    // ---------------------
    // | Inbound Responses |
    // ---------------------

    /// Handles a response to a request for order info
    pub(crate) async fn handle_order_info_response(
        &self,
        order_info: Vec<NetworkOrder>,
    ) -> Result<(), GossipError> {
        for mut order in order_info.into_iter() {
            let order_id = order.id;

            // Skip local orders, their state is added on wallet update through raft
            // consensus
            let is_local = order.cluster == self.global_state.get_cluster_id()?;
            if is_local {
                log::debug!("skipping local order {order_id}");
                continue;
            }

            // Move fields out of `order_info` before transferring ownership
            let proof = order.validity_proofs.take();

            order.state = NetworkOrderState::Received;
            order.local = is_local;
            self.global_state.add_order(order)?;

            // If there is a proof attached to the order, verify it and transition to
            // `Verified`. If the order is locally managed, the raft consensus will take
            // care of indexing the order
            if let Some(proof_bundle) = proof {
                // Spawn a blocking task to avoid consuming the gossip server's thread pool
                let self_clone = self.clone();
                let bundle_clone = proof_bundle.clone();
                tokio::task::spawn_blocking(move || {
                    block_on(self_clone.verify_validity_proofs(&bundle_clone))
                })
                .await
                .unwrap()?;

                // Update the state of the order to `Verified` by attaching the verified
                // validity proof
                self.global_state.add_order_validity_proof(order_id, proof_bundle)?;
            }
        }

        Ok(())
    }

    // -------------------
    // | Pubsub Messages |
    // -------------------

    /// Handle an orderbook management message
    pub(crate) async fn handle_orderbook_pubsub(
        &self,
        msg: OrderBookManagementMessage,
    ) -> Result<(), GossipError> {
        match msg {
            OrderBookManagementMessage::OrderReceived { order_id, nullifier, cluster } => {
                self.handle_new_order(order_id, nullifier, cluster).await
            },
            OrderBookManagementMessage::OrderProofUpdated { order_id, cluster, proof_bundle } => {
                self.handle_new_validity_proof(order_id, cluster, proof_bundle).await
            },
        }
    }

    /// Handles a newly discovered order added to the book
    async fn handle_new_order(
        &self,
        order_id: OrderIdentifier,
        nullifier: Nullifier,
        cluster: ClusterId,
    ) -> Result<(), GossipError> {
        // Skip local orders, their state is added on wallet update through raft
        let is_local = cluster == self.global_state.get_cluster_id()?;
        if is_local {
            return Ok(());
        }

        // Ensure that the nullifier has not been used for this order
        self.assert_nullifier_unused(nullifier).await?;
        self.global_state.add_order(NetworkOrder::new(order_id, nullifier, cluster, is_local))?;
        Ok(())
    }

    /// Handles a new validity proof attached to an order
    ///
    /// TODO: We also need to sanity check the statement variables with the
    /// contract state, e.g. merkle root, nullifiers, etc.
    async fn handle_new_validity_proof(
        &self,
        order_id: OrderIdentifier,
        cluster: ClusterId,
        proof_bundle: OrderValidityProofBundle,
    ) -> Result<(), GossipError> {
        // Skip local orders, their state is added on wallet update through raft
        let is_local = cluster == self.global_state.get_cluster_id()?;
        if is_local {
            return Ok(());
        }

        // Verify the proof
        let bundle_clone = proof_bundle.clone();
        let self_clone = self.clone();

        tokio::task::spawn_blocking(move || {
            block_on(self_clone.verify_validity_proofs(&bundle_clone))
        })
        .await
        .unwrap()?;

        // Add the order to the book in the `Validated` state
        if !self.global_state.contains_order(&order_id)? {
            self.global_state.add_order(NetworkOrder::new(
                order_id,
                proof_bundle.reblind_proof.statement.original_shares_nullifier,
                cluster,
                is_local,
            ))?;
        }

        self.global_state.add_order_validity_proof(order_id, proof_bundle)?;

        Ok(())
    }

    // -----------
    // | Helpers |
    // -----------

    /// Verify the validity proofs (`VALID REBLIND` and `VALID COMMITMENTS`) of
    /// an incoming order
    ///
    /// Aside from proof verification, this involves validating the statement
    /// variables (e.g. merkle root) for the proof
    async fn verify_validity_proofs(
        &self,
        proof_bundle: &OrderValidityProofBundle,
    ) -> Result<(), GossipError> {
        // Clone the proof out from behind their references so that the verifier may
        // take ownership
        let reblind_proof = proof_bundle.copy_reblind_proof();
        let commitment_proof = proof_bundle.copy_commitment_proof();
        let link_proof = &proof_bundle.linking_proof;

        // Check that the proof shares' nullifiers are unused
        self.assert_nullifier_unused(reblind_proof.statement.original_shares_nullifier).await?;

        // Check that the Merkle root is a valid historical root
        if !self
            .arbitrum_client()
            .check_merkle_root_valid(reblind_proof.statement.merkle_root)
            .await
            .map_err(err_str!(GossipError::Arbitrum))?
        {
            return Err(GossipError::ValidCommitmentVerification(
                ERR_INVALID_MERKLE_ROOT.to_string(),
            ));
        }

        // Verify the reblind proof
        verify_singleprover_proof::<SizedValidReblind>(
            reblind_proof.statement,
            &reblind_proof.proof,
        )
        .map_err(err_str!(GossipError::ValidReblindVerification))?;

        // Validate the commitment proof
        verify_singleprover_proof::<SizedValidCommitments>(
            commitment_proof.statement,
            &commitment_proof.proof,
        )
        .map_err(err_str!(GossipError::ValidCommitmentVerification))?;

        // Validate the proof link between the `VALID REBLIND` and `VALID COMMITMENTS`
        // proofs
        validate_sized_commitments_reblind_link(
            link_proof,
            &reblind_proof.proof,
            &commitment_proof.proof,
        )
        .map_err(err_str!(GossipError::CommitmentsReblindLinkVerification))
    }

    /// Assert that a nullifier is unused in the contract, returns a GossipError
    /// if the nullifier has been used
    async fn assert_nullifier_unused(&self, nullifier: Nullifier) -> Result<(), GossipError> {
        self.arbitrum_client()
            .check_nullifier_used(nullifier)
            .await
            .map(|res| {
                if res {
                    Err(GossipError::NullifierUsed(ERR_NULLIFIER_USED.to_string()))
                } else {
                    Ok(())
                }
            })
            .map_err(|err| GossipError::Arbitrum(err.to_string()))?
    }
}
