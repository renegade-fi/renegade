//! Defines pubsub message handlers

use gossip_api::{
    cluster_management::{ClusterManagementMessage, ReplicatedMessage},
    gossip::{AuthenticatedPubsubMessage, PubsubMessage},
    orderbook_management::OrderBookManagementMessage,
};
use job_types::{
    gossip_server::{ClusterManagementJob, GossipServerJob, OrderBookManagementJob},
    handshake_manager::HandshakeExecutionJob,
};
use libp2p::gossipsub::{Message as GossipsubMessage, Sha256Topic};

use crate::error::NetworkManagerError;

use super::{BufferedPubsubMessage, NetworkManagerExecutor, ERR_SIG_VERIFY};

impl NetworkManagerExecutor {
    /// Forward an outbound pubsub message to the network
    pub(super) fn forward_outbound_pubsub(
        &mut self,
        topic: String,
        message: PubsubMessage,
    ) -> Result<(), NetworkManagerError> {
        // If the gossip server has not warmed up the local node into the network,
        // buffer the pubsub message for forwarding after the warmup
        if !self.warmup_finished {
            self.warmup_buffer.push(BufferedPubsubMessage { topic, message });
            return Ok(());
        }

        // If we require a signature on the message attach one
        let req_body = AuthenticatedPubsubMessage::new_with_body(message, &self.cluster_key)
            .map_err(|err| NetworkManagerError::Authentication(err.to_string()))?;

        // Forward to the network
        let topic = Sha256Topic::new(topic);
        self.swarm
            .behaviour_mut()
            .pubsub
            .publish(topic, req_body)
            .map_err(|err| NetworkManagerError::Network(err.to_string()))?;
        Ok(())
    }

    /// Handle an incoming network request for a pubsub message
    pub(super) fn handle_inbound_pubsub_message(
        &mut self,
        message: GossipsubMessage,
    ) -> Result<(), NetworkManagerError> {
        // Deserialize into API types and verify auth
        let event: AuthenticatedPubsubMessage =
            message.data.try_into().map_err(NetworkManagerError::Serialization)?;

        if !event.verify_cluster_auth(&self.cluster_key.public) {
            return Err(NetworkManagerError::Authentication(ERR_SIG_VERIFY.to_string()));
        }

        match event.body {
            PubsubMessage::ClusterManagement { cluster_id, message } => {
                match message {
                    // --------------------
                    // | Cluster Metadata |
                    // --------------------

                    // Forward the management message to the gossip server for processing
                    ClusterManagementMessage::Join(join_request) => {
                        // Forward directly
                        self.gossip_work_queue
                            .send(GossipServerJob::Cluster(
                                ClusterManagementJob::ClusterJoinRequest(cluster_id, join_request),
                            ))
                            .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string()))?;
                    },

                    // Forward the management message to the gossip server for processing
                    ClusterManagementMessage::Replicated(ReplicatedMessage {
                        wallets,
                        peer_id,
                    }) => {
                        // Forward one job per replicated wallet; makes gossip server implementation
                        // cleaner
                        for wallet_id in wallets.into_iter() {
                            self.gossip_work_queue
                                .send(GossipServerJob::Cluster(
                                    ClusterManagementJob::AddWalletReplica { wallet_id, peer_id },
                                ))
                                .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string()))?;
                        }
                    },

                    // ---------
                    // | Match |
                    // ---------

                    // Forward the cache sync message to the handshake manager to update the local
                    // cache copy
                    ClusterManagementMessage::CacheSync(order1, order2) => self
                        .handshake_work_queue
                        .send(HandshakeExecutionJob::CacheEntry { order1, order2 })
                        .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string()))?,

                    // Forward the match in progress message to the handshake manager so that it can
                    // avoid scheduling a duplicate handshake for the given
                    // order pair
                    ClusterManagementMessage::MatchInProgress(order1, order2) => self
                        .handshake_work_queue
                        .send(HandshakeExecutionJob::PeerMatchInProgress { order1, order2 })
                        .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string()))?,

                    // -------------
                    // | Orderbook |
                    // -------------

                    // Forward a request for validity proofs to the gossip server to check for
                    // locally available proofs
                    ClusterManagementMessage::RequestOrderValidityProof(req) => {
                        self.gossip_work_queue
                            .send(GossipServerJob::Cluster(
                                ClusterManagementJob::ShareValidityProofs(req),
                            ))
                            .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string()))?;
                    },

                    // Forward a request to the gossip server to share validity proof witness
                    ClusterManagementMessage::RequestOrderValidityWitness(req) => self
                        .gossip_work_queue
                        .send(GossipServerJob::OrderBookManagement(
                            OrderBookManagementJob::OrderWitness {
                                order_id: req.order_id,
                                requesting_peer: req.sender,
                            },
                        ))
                        .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string()))?,
                }
            },
            PubsubMessage::OrderBookManagement(msg) => match msg {
                OrderBookManagementMessage::OrderReceived { order_id, nullifier, cluster } => self
                    .gossip_work_queue
                    .send(GossipServerJob::OrderBookManagement(
                        OrderBookManagementJob::OrderReceived { order_id, nullifier, cluster },
                    ))
                    .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string()))?,

                OrderBookManagementMessage::OrderProofUpdated {
                    order_id,
                    cluster,
                    proof_bundle,
                } => self
                    .gossip_work_queue
                    .send(GossipServerJob::OrderBookManagement(
                        OrderBookManagementJob::OrderProofUpdated {
                            order_id,
                            cluster,
                            proof_bundle,
                        },
                    ))
                    .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string()))?,
            },
        }

        Ok(())
    }
}
