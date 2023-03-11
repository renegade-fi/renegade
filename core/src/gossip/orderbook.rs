//! Groups handlers for updating and managing order book state in response to
//! events elsewhere in the local node or the network

use std::str::FromStr;

use circuits::{types::wallet::Nullifier, verify_singleprover_proof};
use crypto::fields::{biguint_to_starknet_felt, scalar_to_biguint, starknet_felt_to_biguint};
use libp2p::request_response::ResponseChannel;
use starknet::core::{
    types::{BlockId, CallFunction, FieldElement as StarknetFieldElement},
    utils::get_selector_from_name,
};
use starknet_providers::Provider;
use tracing::log;

use crate::{
    api::{
        cluster_management::{ClusterManagementMessage, ValidityWitnessRequest},
        gossip::{
            AuthenticatedGossipResponse, GossipOutbound, GossipRequest, GossipResponse,
            PubsubMessage,
        },
        orderbook_management::OrderInfoResponse,
    },
    proof_generation::jobs::ValidCommitmentsBundle,
    state::{NetworkOrder, OrderIdentifier},
    types::{SizedValidCommitments, SizedValidCommitmentsWitness},
};

use super::{
    errors::GossipError,
    jobs::OrderBookManagementJob,
    server::GossipProtocolExecutor,
    types::{ClusterId, WrappedPeerId},
};

/// The darkpool contract's function name for checking nullifiers
const NULLIFIER_USED_FUNCTION: &str = "is_nullifier_used";

impl GossipProtocolExecutor {
    /// Dispatches messages from the cluster regarding order book management
    pub(super) async fn handle_order_book_management_job(
        &self,
        message: OrderBookManagementJob,
    ) -> Result<(), GossipError> {
        match message {
            OrderBookManagementJob::OrderInfo {
                order_id,
                response_channel,
            } => {
                self.handle_order_info_request(order_id, response_channel)
                    .await
            }

            OrderBookManagementJob::OrderInfoResponse { info, .. } => {
                if let Some(order_info) = info {
                    self.handle_order_info_response(order_info).await?;
                }

                Ok(())
            }

            OrderBookManagementJob::OrderReceived {
                order_id,
                match_nullifier,
                cluster,
            } => {
                self.handle_new_order(order_id, match_nullifier, cluster)
                    .await
            }

            OrderBookManagementJob::OrderProofUpdated {
                order_id,
                cluster,
                proof,
            } => {
                self.handle_new_validity_proof(order_id, cluster, proof)
                    .await
            }

            OrderBookManagementJob::OrderWitness {
                order_id,
                requesting_peer,
            } => {
                self.handle_validity_witness_request(order_id, requesting_peer)
                    .await
            }

            OrderBookManagementJob::OrderWitnessResponse { order_id, witness } => {
                self.handle_validity_witness_response(order_id, witness)
                    .await;
                Ok(())
            }
        }
    }

    /// Handles a request for order information from a peer
    async fn handle_order_info_request(
        &self,
        order_id: OrderIdentifier,
        response_channel: ResponseChannel<AuthenticatedGossipResponse>,
    ) -> Result<(), GossipError> {
        let order_info = self
            .global_state
            .read_order_book()
            .await
            .get_order_info(&order_id)
            .await;

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
    async fn handle_order_info_response(
        &self,
        mut order_info: NetworkOrder,
    ) -> Result<(), GossipError> {
        // Ensure that the nullifier has not been used for this order
        if !self
            .check_nullifier_unused(order_info.match_nullifier)
            .await?
        {
            log::info!("received order with spent nullifier, skipping...");
            return Ok(());
        }

        // If there is a proof attached to the order, verify it
        let is_local = order_info.cluster == self.global_state.local_cluster_id;
        if let Some(proof_bundle) = order_info.valid_commit_proof.clone() {
            // We can trust local (i.e. originating from cluster peers) proofs
            if !is_local {
                tokio::task::spawn_blocking(move || {
                    verify_singleprover_proof::<SizedValidCommitments>(
                        proof_bundle.statement,
                        proof_bundle.commitment,
                        proof_bundle.proof,
                    )
                })
                .await
                .unwrap()
                .map_err(|err| GossipError::ValidCommitmentVerification(err.to_string()))?;
            }

            // If the order is a locally managed order, the local peer also needs a copy of the witness
            // so that it may link commitments between the validity proof and subsequent match/encryption
            // proofs
            if is_local {
                self.request_order_witness(order_info.id)?;
            }
        }

        order_info.local = is_local;
        self.global_state.add_order(order_info).await;

        Ok(())
    }

    /// Handles a newly discovered order added to the book
    async fn handle_new_order(
        &self,
        order_id: OrderIdentifier,
        match_nullifier: Nullifier,
        cluster: ClusterId,
    ) -> Result<(), GossipError> {
        // Ensure that the nullifier has not been used for this order
        if !self.check_nullifier_unused(match_nullifier).await? {
            log::info!("received order with spent nullifier, skipping...");
            return Ok(());
        }

        let is_local = cluster == self.global_state.local_cluster_id;
        self.global_state
            .add_order(NetworkOrder::new(
                order_id,
                match_nullifier,
                cluster,
                is_local,
            ))
            .await;
        Ok(())
    }

    /// Handles a new validity proof attached to an order
    ///
    /// TODO: We also need to sanity check the statement variables with the contract state,
    /// e.g. merkle root, nullifiers, etc.
    async fn handle_new_validity_proof(
        &self,
        order_id: OrderIdentifier,
        cluster: ClusterId,
        proof_bundle: ValidCommitmentsBundle,
    ) -> Result<(), GossipError> {
        // Ensure that the nullifier has not been used for this order
        if !self
            .check_nullifier_unused(proof_bundle.statement.nullifier)
            .await?
        {
            log::info!("received order with spent nullifier, skipping...");
            return Ok(());
        }

        let is_local = cluster.eq(&self.global_state.local_cluster_id);

        // Verify the proof
        if !is_local {
            let bundle_clone = proof_bundle.clone();
            tokio::task::spawn_blocking(move || {
                verify_singleprover_proof::<SizedValidCommitments>(
                    bundle_clone.statement,
                    bundle_clone.commitment,
                    bundle_clone.proof,
                )
            })
            .await
            .unwrap()
            .map_err(|err| GossipError::ValidCommitmentVerification(err.to_string()))?;
        }

        // Add the order to the book in the `Validated` state
        if !self
            .global_state
            .read_order_book()
            .await
            .contains_order(&order_id)
        {
            self.global_state
                .add_order(NetworkOrder::new(
                    order_id,
                    proof_bundle.statement.nullifier,
                    cluster,
                    is_local,
                ))
                .await;
        }

        self.global_state
            .add_order_validity_proof(&order_id, proof_bundle)
            .await;

        // If the order is locally managed, also fetch the wintess used in the proof,
        // this is used for proof linking. I.e. the local node needs the commitment parameters
        // for each witness element so that it may share commitments with future proofs
        if is_local {
            self.request_order_witness(order_id)?;
        }

        Ok(())
    }

    /// Requests a copy of the witness used in an order's validity proof for a locally
    /// managed order
    fn request_order_witness(&self, order_id: OrderIdentifier) -> Result<(), GossipError> {
        let message =
            ClusterManagementMessage::RequestOrderValidityWitness(ValidityWitnessRequest {
                order_id,
                sender: self.global_state.local_peer_id,
            });

        self.network_channel
            .send(GossipOutbound::Pubsub {
                topic: self.global_state.local_cluster_id.get_management_topic(),
                message: PubsubMessage::ClusterManagement {
                    cluster_id: self.global_state.local_cluster_id.clone(),
                    message,
                },
            })
            .map_err(|err| GossipError::SendMessage(err.to_string()))
    }

    /// Handles a request for a validity proof witness from a peer
    async fn handle_validity_witness_request(
        &self,
        order_id: OrderIdentifier,
        requesting_peer: WrappedPeerId,
    ) -> Result<(), GossipError> {
        // Sanity check that the requesting peer is part of the cluster,
        // authentication of the message is done at the network manager level,
        // so this check is a bit redundant, but worth doing
        {
            let info = self
                .global_state
                .read_peer_index()
                .await
                .get_peer_info(&requesting_peer)
                .await
                .ok_or_else(|| {
                    GossipError::MissingState("peer info not found in state".to_string())
                })?;

            if info.get_cluster_id() != self.global_state.local_cluster_id {
                return Ok(());
            }
        } // peer_index lock released

        // If the local peer has a copy of the witness stored locally, send it to the peer
        if let Some(order_info) = self
            .global_state
            .read_order_book()
            .await
            .get_order_info(&order_id)
            .await
        && let Some(witness) = order_info.valid_commit_witness
        {
            self.network_channel
                .send(GossipOutbound::Request { peer_id: requesting_peer, message: GossipRequest::ValidityWitness {
                    order_id, witness
                }})
                .map_err(|err| GossipError::SendMessage(err.to_string()))?;
        }

        Ok(())
    }

    /// Handle a response from a peer containing a witness for `VALID COMMITMENTS`
    async fn handle_validity_witness_response(
        &self,
        order_id: OrderIdentifier,
        witness: SizedValidCommitmentsWitness,
    ) {
        self.global_state
            .read_order_book()
            .await
            .attach_validity_proof_witness(&order_id, witness)
            .await;
    }

    /// Checks that a nullifier has not been seen on-chain for a given order
    async fn check_nullifier_unused(&self, nullifier: Nullifier) -> Result<bool, GossipError> {
        // TODO: Remove this in favor of bigint implementation:
        // Take the nullifier modulo the Starknet prime field
        let nullifier_bigint = scalar_to_biguint(&nullifier);
        let modulus_bigint = starknet_felt_to_biguint(&StarknetFieldElement::MAX) + 1u8;
        let nullifier_mod_starknet_prime = nullifier_bigint % modulus_bigint;

        let call = CallFunction {
            contract_address: StarknetFieldElement::from_str(&self.config.contract_address)
                .unwrap(),
            entry_point_selector: get_selector_from_name(NULLIFIER_USED_FUNCTION).unwrap(),
            calldata: vec![biguint_to_starknet_felt(&nullifier_mod_starknet_prime)],
        };
        let res = self
            .starknet_client
            .call_contract(call, BlockId::Pending)
            .await
            .map_err(|err| GossipError::StarknetRequest(err.to_string()))?;

        if res.result[0].eq(&StarknetFieldElement::from(0u8)) {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
