//! Defines handlers for the request-response protocol

use gossip_api::{
    request_response::{
        AuthenticatedGossipRequest, AuthenticatedGossipResponse, GossipRequest, GossipResponse,
    },
    GossipDestination,
};
use libp2p::request_response::{Message as RequestResponseMessage, ResponseChannel};
use libp2p::PeerId;

use crate::error::NetworkManagerError;

use super::NetworkManagerExecutor;

impl NetworkManagerExecutor {
    // -----------
    // | Inbound |
    // -----------

    /// Handle an incoming message from the network's request/response protocol
    pub(super) fn handle_inbound_request_response_message(
        &mut self,
        message: RequestResponseMessage<AuthenticatedGossipRequest, AuthenticatedGossipResponse>,
    ) -> Result<(), NetworkManagerError> {
        // Multiplex over request/response message types
        match message {
            // Handle inbound request from another peer
            RequestResponseMessage::Request { request, channel, .. } => {
                // Authenticate the request then dispatch
                request.verify_cluster_auth(&self.cluster_key.public)?;
                match request.body.destination() {
                    GossipDestination::NetworkManager => todo!(),
                    GossipDestination::GossipServer => todo!(),
                    GossipDestination::HandshakeManager => todo!(),
                }
            },

            // Handle inbound response
            RequestResponseMessage::Response { response, .. } => {
                response.verify_cluster_auth(&self.cluster_key.public)?;
                match response.body.destination() {
                    GossipDestination::NetworkManager => todo!(),
                    GossipDestination::GossipServer => todo!(),
                    GossipDestination::HandshakeManager => todo!(),
                }
            },
        }
    }

    // ------------
    // | Outbound |
    // ------------

    /// Handle an outbound request
    pub(crate) fn handle_outbound_req(
        &mut self,
        peer: PeerId,
        req: GossipRequest,
    ) -> Result<(), NetworkManagerError> {
        // Authenticate the request
        let authenticate_req = AuthenticatedGossipRequest::new_with_body(req, &self.cluster_key)?;
        self.swarm.behaviour_mut().request_response.send_request(&peer, authenticate_req);

        Ok(())
    }

    /// Handle an outbound response
    pub(crate) fn handle_outbound_resp(
        &mut self,
        resp: GossipResponse,
        chan: ResponseChannel<AuthenticatedGossipResponse>,
    ) -> Result<(), NetworkManagerError> {
        // Authenticate the response
        let authenticate_resp =
            AuthenticatedGossipResponse::new_with_body(resp, &self.cluster_key)?;

        self.swarm
            .behaviour_mut()
            .request_response
            .send_response(chan, authenticate_resp)
            .map_err(|_| NetworkManagerError::Network("error sending response".to_string()))
    }
}
