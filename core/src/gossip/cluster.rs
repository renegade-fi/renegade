//! Groups handlers for gossiping about cluster management events


use crate::{
    api::{
        cluster_management::{
            ClusterJoinMessage, ClusterManagementMessage, ReplicateRequestBody, ReplicatedMessage,
            ValidityProofRequest,
        },
        gossip::{GossipOutbound, GossipRequest, PubsubMessage},
    },
    proof_generation::jobs::ValidCommitmentsBundle,
    state::{
        wallet::{Wallet, WalletIdentifier},
        OrderIdentifier,
    },
};

use super::{
    errors::GossipError,
    jobs::ClusterManagementJob,
    server::GossipProtocolExecutor,
    types::{ClusterId, PeerInfo, WrappedPeerId},
};

/// Cluster management implementation of the protocol executor
impl GossipProtocolExecutor {
    /// Handles an incoming cluster management job
    pub(super) fn handle_cluster_management_job(
        &self,
        job: ClusterManagementJob,
    ) -> Result<(), GossipError> {
        match job {
            ClusterManagementJob::ClusterAuthSuccess(cluster_id, peer_id, peer_info) => {
                self.add_peer_to_cluster(peer_id, peer_info, cluster_id)?;
            }

            ClusterManagementJob::ClusterJoinRequest(cluster_id, req) => {
                self.handle_cluster_join_job(cluster_id, req)?;
            }

            ClusterManagementJob::ReplicateRequest(req) => {
                self.handle_replicate_request(req)?;
            }

            ClusterManagementJob::AddWalletReplica { wallet_id, peer_id } => {
                self.handle_add_replica_job(peer_id, wallet_id)
            }

            ClusterManagementJob::ShareValidityProofs(req) => {
                self.handle_share_validity_proofs_job(req)?;
            }

            ClusterManagementJob::UpdateValidityProof(order_id, proof) => {
                self.handle_updated_validity_proof(order_id, proof);
            }
        }

        Ok(())
    }

    /// Handles a cluster management job to add a new node to the local peer's cluster
    fn handle_cluster_join_job(
        &self,
        cluster_id: ClusterId,
        message: ClusterJoinMessage,
    ) -> Result<(), GossipError> {
        // Ignore messages sent for a different cluster
        if cluster_id != self.global_state.local_cluster_id {
            return Ok(());
        }

        // Add the peer to the cluster metadata
        // Move out of message to avoid clones
        let peer_id = message.peer_id;
        let peer_info = message.peer_info;
        let peer_addr = message.addr;

        self.add_peer_to_cluster(peer_id, peer_info, cluster_id.clone())?;

        // Add the peer to the known peers index
        self.global_state
            .add_single_peer(peer_id, PeerInfo::new(peer_id, cluster_id, peer_addr));

        // Request that the peer replicate all locally replicated wallets
        let wallets = self.global_state.read_wallet_index().get_all_wallets();
        self.send_replicate_request(message.peer_id, wallets)
    }

    /// Add a peer to the given cluster
    fn add_peer_to_cluster(
        &self,
        peer_id: WrappedPeerId,
        peer_info: PeerInfo,
        cluster_id: ClusterId,
    ) -> Result<(), GossipError> {
        // Ignore messages sent for a different cluster
        if cluster_id != self.global_state.local_cluster_id {
            return Ok(());
        }

        // Add the peer to the known peers index
        self.global_state.add_single_peer(peer_id, peer_info);

        // The cluster join request is authenticated at the network layer
        // by the `NetworkManager`, so no authentication needs to be done.
        // Simply update the local cluster metadata to reflect the new node's membership
        self.global_state.add_cluster_peer(peer_id);

        // Request that the peer replicate all locally replicated wallets
        let wallets = self.global_state.read_wallet_index().get_all_wallets();
        self.send_replicate_request(peer_id, wallets)
    }

    /// Send a request to the given peer to replicate a set of wallets
    fn send_replicate_request(
        &self,
        peer: WrappedPeerId,
        wallets: Vec<Wallet>,
    ) -> Result<(), GossipError> {
        if wallets.is_empty() {
            return Ok(());
        }

        self.network_channel
            .send(GossipOutbound::Request {
                peer_id: peer,
                message: GossipRequest::Replicate(ReplicateRequestBody { wallets }),
            })
            .map_err(|err| GossipError::SendMessage(err.to_string()))
    }

    /// Handles a request from a peer to replicate a given set of wallets
    fn handle_replicate_request(&self, req: ReplicateRequestBody) -> Result<(), GossipError> {
        if req.wallets.is_empty() {
            return Ok(());
        }

        // Add wallets to global state
        self.global_state.add_wallets(req.wallets.clone());

        // Update cluster management bookkeeping
        let topic = self
            .global_state
            .read_cluster_metadata()
            .id
            .get_management_topic();

        // Broadcast a message to the network indicating that the wallet is now replicated
        let replicated_message = PubsubMessage::ClusterManagement {
            cluster_id: self.global_state.local_cluster_id.clone(),
            message: ClusterManagementMessage::Replicated(ReplicatedMessage {
                wallets: req.wallets.iter().map(|wallet| wallet.wallet_id).collect(),
                peer_id: self.global_state.local_peer_id(),
            }),
        };
        self.network_channel
            .send(GossipOutbound::Pubsub {
                topic: topic.clone(),
                message: replicated_message,
            })
            .map_err(|err| GossipError::SendMessage(err.to_string()))?;

        // Broadcast a message requesting proofs for all new orders
        let mut orders_needing_proofs = Vec::new();
        {
            let locked_order_state = self.global_state.read_order_book();
            for wallet in req.wallets.iter() {
                for order_id in wallet.orders.keys() {
                    if !locked_order_state.has_validity_proof(order_id) {
                        orders_needing_proofs.push(*order_id);
                    }
                }
            }
        } // locked_order_state released

        let proof_request = PubsubMessage::ClusterManagement {
            cluster_id: self.global_state.local_cluster_id.clone(),
            message: ClusterManagementMessage::RequestOrderValidityProof(ValidityProofRequest {
                order_ids: orders_needing_proofs,
                sender: self.global_state.local_peer_id,
            }),
        };
        self.network_channel
            .send(GossipOutbound::Pubsub {
                topic,
                message: proof_request,
            })
            .map_err(|err| GossipError::SendMessage(err.to_string()))?;

        Ok(())
    }

    /// Handles an incoming job to update a wallet's replicas with a newly added peer
    fn handle_add_replica_job(&self, peer_id: WrappedPeerId, wallet_id: WalletIdentifier) {
        self.global_state
            .read_wallet_index()
            .add_replica(&wallet_id, peer_id);
    }

    /// Handles an incoming job to check for validity proofs and send them to a cluster peer
    fn handle_share_validity_proofs_job(
        &self,
        req: ValidityProofRequest,
    ) -> Result<(), GossipError> {
        // Check the local order book for any requested proofs that the local peer has stored
        let mut outbound_messages = Vec::new();
        {
            let locked_order_book = self.global_state.read_order_book();
            for order_id in req.order_ids.iter() {
                if let Some(proof) = locked_order_book.get_validity_proof(order_id) {
                    outbound_messages.push(GossipRequest::ValidityProof {
                        order_id: *order_id,
                        proof,
                    });
                }
            }
        } // locked_order_book released

        // Forward outbound proof messages to the network manager
        for message in outbound_messages.into_iter() {
            self.network_channel
                .send(GossipOutbound::Request {
                    peer_id: req.sender,
                    message,
                })
                .map_err(|err| GossipError::SendMessage(err.to_string()))?;
        }

        Ok(())
    }

    /// Handle a message from a cluster peer that sends a proof of `VALID COMMITMENTS` for an order
    fn handle_updated_validity_proof(
        &self,
        order_id: OrderIdentifier,
        proof: ValidCommitmentsBundle,
    ) {
        self.global_state
            .read_order_book()
            .update_order_validity_proof(&order_id, proof);
    }
}
