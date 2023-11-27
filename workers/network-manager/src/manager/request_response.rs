//! Defines handlers for the request-response protocol

use common::types::gossip::WrappedPeerId;
use gossip_api::{
    gossip::{
        AuthenticatedGossipRequest, AuthenticatedGossipResponse, GossipOutbound, GossipRequest,
        GossipResponse,
    },
    orderbook_management::OrderInfoResponse,
};
use job_types::{
    gossip_server::{ClusterManagementJob, GossipServerJob, OrderBookManagementJob},
    handshake_manager::HandshakeExecutionJob,
};
use libp2p::request_response::Message as RequestResponseMessage;
use libp2p::PeerId;

use crate::error::NetworkManagerError;

use super::{NetworkManagerExecutor, ERR_SIG_VERIFY};

impl NetworkManagerExecutor {
    /// Handle an incoming message from the network's request/response protocol
    pub(super) fn handle_inbound_request_response_message(
        &mut self,
        peer_id: PeerId,
        message: RequestResponseMessage<AuthenticatedGossipRequest, AuthenticatedGossipResponse>,
    ) -> Result<(), NetworkManagerError> {
        // Multiplex over request/response message types
        match message {
            // Handle inbound request from another peer
            RequestResponseMessage::Request { request, channel, .. } => {
                // Authenticate the request
                if !request.verify_cluster_auth(&self.cluster_key.public) {
                    return Err(NetworkManagerError::Authentication(ERR_SIG_VERIFY.to_string()));
                }

                match request.body {
                    // Forward the bootstrap request directly to the gossip server
                    GossipRequest::Bootstrap(req) => self
                        .gossip_work_queue
                        .send(GossipServerJob::Bootstrap(req, channel))
                        .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string())),

                    GossipRequest::Heartbeat(heartbeat_message) => self
                        .gossip_work_queue
                        .send(GossipServerJob::HandleHeartbeatReq {
                            peer_id: WrappedPeerId(peer_id),
                            message: heartbeat_message,
                            channel,
                        })
                        .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string())),

                    GossipRequest::Handshake { request_id, message } => self
                        .handshake_work_queue
                        .send(HandshakeExecutionJob::ProcessHandshakeMessage {
                            request_id,
                            peer_id: WrappedPeerId(peer_id),
                            message,
                            response_channel: Some(channel),
                        })
                        .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string())),

                    GossipRequest::OrderInfo(req) => self
                        .gossip_work_queue
                        .send(GossipServerJob::OrderBookManagement(
                            OrderBookManagementJob::OrderInfo {
                                order_id: req.order_id,
                                response_channel: channel,
                            },
                        ))
                        .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string())),

                    GossipRequest::Replicate(replicate_message) => {
                        self.gossip_work_queue
                            .send(GossipServerJob::Cluster(ClusterManagementJob::ReplicateRequest(
                                replicate_message,
                            )))
                            .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string()))?;

                        // Send a simple ack back to avoid closing the channel
                        self.swarm
                            .behaviour_mut()
                            .request_response
                            .send_response(channel, AuthenticatedGossipResponse::new_ack())
                            .map_err(|_| {
                                NetworkManagerError::Network("error sending Ack".to_string())
                            })
                    },

                    GossipRequest::ValidityProof { order_id, proof_bundle } => {
                        self.gossip_work_queue
                            .send(GossipServerJob::Cluster(
                                ClusterManagementJob::UpdateValidityProof(order_id, proof_bundle),
                            ))
                            .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string()))
                    },

                    GossipRequest::ValidityWitness { order_id, witness } => {
                        self.gossip_work_queue
                            .send(GossipServerJob::OrderBookManagement(
                                OrderBookManagementJob::OrderWitnessResponse { order_id, witness },
                            ))
                            .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string()))?;

                        // Send back an ack
                        self.handle_outbound_message(GossipOutbound::Response {
                            channel,
                            message: GossipResponse::Ack,
                        })
                    },

                    GossipRequest::WalletUpdate { wallet } => {
                        self.gossip_work_queue
                            .send(GossipServerJob::WalletUpdate { wallet })
                            .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string()))?;

                        // Send back an ack
                        self.handle_outbound_message(GossipOutbound::Response {
                            channel,
                            message: GossipResponse::Ack,
                        })
                    },
                }
            },

            // Handle inbound response
            RequestResponseMessage::Response { response, .. } => {
                if !response.verify_cluster_auth(&self.cluster_key.public) {
                    return Err(NetworkManagerError::Authentication(ERR_SIG_VERIFY.to_string()));
                }

                match response.body {
                    GossipResponse::Ack => Ok(()),

                    GossipResponse::Heartbeat(heartbeat_message) => self
                        .gossip_work_queue
                        .send(GossipServerJob::HandleHeartbeatResp {
                            peer_id: WrappedPeerId(peer_id),
                            message: heartbeat_message,
                        })
                        .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string())),

                    GossipResponse::Handshake { request_id, message } => self
                        .handshake_work_queue
                        .send(HandshakeExecutionJob::ProcessHandshakeMessage {
                            request_id,
                            peer_id: WrappedPeerId(peer_id),
                            message,
                            // The handshake should response via a new request sent on the network
                            // manager channel
                            response_channel: None,
                        })
                        .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string())),

                    GossipResponse::OrderInfo(OrderInfoResponse { order_id, info }) => self
                        .gossip_work_queue
                        .send(GossipServerJob::OrderBookManagement(
                            OrderBookManagementJob::OrderInfoResponse { order_id, info },
                        ))
                        .map_err(|err| NetworkManagerError::EnqueueJob(err.to_string())),
                }
            },
        }
    }
}
