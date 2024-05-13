//! Defines handlers for the request-response protocol

use common::types::gossip::WrappedPeerId;
use gossip_api::{
    request_response::{
        AuthenticatedGossipRequest, AuthenticatedGossipResponse, GossipRequest, GossipResponse,
    },
    GossipDestination,
};
use job_types::{gossip_server::GossipServerJob, network_manager::NetworkResponseChannel};
use libp2p::request_response::{Message as RequestResponseMessage, ResponseChannel};
use libp2p::PeerId;
use util::err_str;

use crate::error::NetworkManagerError;

use super::{behavior::BehaviorJob, NetworkManagerExecutor};

impl NetworkManagerExecutor {
    // -----------
    // | Inbound |
    // -----------

    /// Handle an incoming message from the network's request/response protocol
    pub(super) fn handle_inbound_request_response_message(
        &self,
        peer: PeerId,
        message: RequestResponseMessage<AuthenticatedGossipRequest, AuthenticatedGossipResponse>,
    ) -> Result<(), NetworkManagerError> {
        let peer = WrappedPeerId(peer);

        // Multiplex over request/response message types
        match message {
            // Handle inbound request from another peer
            RequestResponseMessage::Request { request, channel, .. } => {
                // Authenticate the request then dispatch
                request.verify_cluster_auth(&self.cluster_key.public)?;
                let body = request.body;
                match body.destination() {
                    GossipDestination::NetworkManager => {
                        self.handle_internal_request(body, channel)
                    },
                    GossipDestination::GossipServer => {
                        let job = GossipServerJob::NetworkRequest(peer, body, channel);
                        self.gossip_work_queue
                            .send(job)
                            .map_err(err_str!(NetworkManagerError::EnqueueJob))
                    },
                    GossipDestination::HandshakeManager => todo!(),
                }
            },

            // Handle inbound response
            RequestResponseMessage::Response { response, .. } => {
                response.verify_cluster_auth(&self.cluster_key.public)?;
                let body = response.body;
                match body.destination() {
                    GossipDestination::NetworkManager => self.handle_internal_response(body),
                    GossipDestination::GossipServer => {
                        let job = GossipServerJob::NetworkResponse(peer, body);
                        self.gossip_work_queue
                            .send(job)
                            .map_err(err_str!(NetworkManagerError::EnqueueJob))
                    },
                    GossipDestination::HandshakeManager => todo!(),
                }
            },
        }
    }

    /// Handle an internally routed request
    fn handle_internal_request(
        &self,
        req: GossipRequest,
        chan: ResponseChannel<AuthenticatedGossipResponse>,
    ) -> Result<(), NetworkManagerError> {
        match req {
            GossipRequest::Ack => Ok(()),
            GossipRequest::Raft(raft_message) => self.handle_raft_message(raft_message, chan),
            _ => Err(NetworkManagerError::UnhandledRequest(format!(
                "unhandled internal request: {req:?}",
            ))),
        }
    }

    /// Handle a raft message
    fn handle_raft_message(
        &self,
        msg_buf: Vec<u8>,
        chan: ResponseChannel<AuthenticatedGossipResponse>,
    ) -> Result<(), NetworkManagerError> {
        todo!()
    }

    /// Handle an internally routed response
    #[allow(clippy::needless_pass_by_value)]
    fn handle_internal_response(&self, resp: GossipResponse) -> Result<(), NetworkManagerError> {
        match resp {
            GossipResponse::Ack => Ok(()),
            _ => Err(NetworkManagerError::UnhandledRequest(format!(
                "unhandled internal response: {resp:?}",
            ))),
        }
    }

    // ------------
    // | Outbound |
    // ------------

    /// Handle an outbound request
    pub(crate) fn handle_outbound_req(
        &self,
        peer: PeerId,
        req: GossipRequest,
        chan: Option<NetworkResponseChannel>,
    ) -> Result<(), NetworkManagerError> {
        // Authenticate the request
        let authenticate_req = AuthenticatedGossipRequest::new_with_body(req, &self.cluster_key)?;
        self.send_behavior(BehaviorJob::SendReq(peer, authenticate_req, chan))
    }

    /// Handle an outbound response
    pub(crate) fn handle_outbound_resp(
        &self,
        resp: GossipResponse,
        chan: ResponseChannel<AuthenticatedGossipResponse>,
    ) -> Result<(), NetworkManagerError> {
        // Authenticate the response
        let authenticate_resp =
            AuthenticatedGossipResponse::new_with_body(resp, &self.cluster_key)?;
        self.send_behavior(BehaviorJob::SendResp(chan, authenticate_resp))
    }
}
