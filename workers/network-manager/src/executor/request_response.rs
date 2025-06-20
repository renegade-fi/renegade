//! Defines handlers for the request-response protocol

use std::time::{Duration, Instant};

use common::types::gossip::WrappedPeerId;
use gossip_api::{
    request_response::{
        AuthenticatedGossipRequest, AuthenticatedGossipResponse, GossipRequest, GossipRequestType,
        GossipResponse, GossipResponseType,
    },
    GossipDestination,
};
use job_types::{gossip_server::GossipServerJob, network_manager::NetworkResponseChannel};
use libp2p::request_response::{Message as RequestResponseMessage, ResponseChannel};
use libp2p::PeerId;
use tracing::{error, instrument, warn};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use util::{err_str, telemetry::propagation::set_parent_span_from_context};

use crate::error::NetworkManagerError;

use super::{behavior::BehaviorJob, NetworkManagerExecutor};

/// The raft job execution latency at which we log a warning
pub(super) const RAFT_JOB_LATENCY_WARNING_MS: Duration = Duration::from_millis(100);

impl NetworkManagerExecutor {
    // -----------
    // | Inbound |
    // -----------

    /// Handle an incoming message from the network's request/response protocol
    #[instrument(name = "handle_inbound_request_response_message", skip_all, err, fields(peer = %peer))]
    pub(super) async fn handle_inbound_request_response_message(
        &self,
        peer: PeerId,
        message: RequestResponseMessage<AuthenticatedGossipRequest, AuthenticatedGossipResponse>,
    ) -> Result<(), NetworkManagerError> {
        let peer = WrappedPeerId(peer);

        // Multiplex over request/response message types
        match message {
            // Handle inbound request from another peer
            RequestResponseMessage::Request { request, channel, .. } => {
                // Use the request's span if provided
                set_parent_span_from_context(&request.inner.tracing_headers());

                // Authenticate the request
                let pkey = self.cluster_key;
                let ctx = tracing::Span::current().context().clone();
                let request = tokio::task::spawn_blocking(move || {
                    tracing::Span::current().set_parent(ctx);
                    request
                        .verify_cluster_auth(&pkey)
                        .then_some(request)
                        .ok_or_else(NetworkManagerError::hmac_error)
                })
                .await
                .unwrap()?;

                let body = request.inner;
                match body.destination() {
                    GossipDestination::NetworkManager => {
                        self.handle_internal_request(body, channel).await
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
            RequestResponseMessage::Response { request_id, response } => {
                // Use the response's span if provided
                set_parent_span_from_context(&response.inner.tracing_headers());

                // Authenticate the response
                let pkey = self.cluster_key;
                let ctx = tracing::Span::current().context().clone();
                let response = tokio::task::spawn_blocking(move || {
                    tracing::Span::current().set_parent(ctx);
                    response
                        .verify_cluster_auth(&pkey)
                        .then_some(response)
                        .ok_or_else(NetworkManagerError::hmac_error)
                })
                .await
                .unwrap()?;

                let body = response.inner;
                if let Some(chan) = self.response_waiters.pop(request_id).await {
                    if !chan.is_closed() && chan.send(body.clone()).is_err() {
                        error!("error sending response notification for request: {request_id}");
                    }
                }

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
    #[instrument(name = "handle_internal_network_request", skip_all, err)]
    async fn handle_internal_request(
        &self,
        req: GossipRequest,
        chan: ResponseChannel<AuthenticatedGossipResponse>,
    ) -> Result<(), NetworkManagerError> {
        match req.body {
            GossipRequestType::Ack => Ok(()),
            GossipRequestType::Raft(raft_message) => self.handle_raft_req(raft_message, chan).await,
            _ => Err(NetworkManagerError::UnhandledRequest(format!(
                "unhandled internal request: {req:?}",
            ))),
        }
    }

    /// Handle an internally routed response
    #[allow(clippy::needless_pass_by_value)]
    fn handle_internal_response(&self, resp: GossipResponse) -> Result<(), NetworkManagerError> {
        match resp.body {
            GossipResponseType::Ack => Ok(()),
            // The response will be forwarded directly to the raft client via the waiters
            GossipResponseType::Raft(_) => Ok(()),
            _ => Err(NetworkManagerError::UnhandledRequest(format!(
                "unhandled internal response: {resp:?}",
            ))),
        }
    }

    /// Handle a raft request
    async fn handle_raft_req(
        &self,
        msg_buf: Vec<u8>,
        chan: ResponseChannel<AuthenticatedGossipResponse>,
    ) -> Result<(), NetworkManagerError> {
        let start = Instant::now();
        let resp = self
            .global_state
            .handle_raft_req(msg_buf)
            .await
            .map_err(err_str!(NetworkManagerError::State))?;

        let elapsed = start.elapsed();
        if elapsed > RAFT_JOB_LATENCY_WARNING_MS {
            warn!("raft request took: {elapsed:.2?}");
        }

        let resp = GossipResponseType::Raft(resp.to_bytes()?);
        self.handle_outbound_resp(resp.into(), chan).await
    }

    // ------------
    // | Outbound |
    // ------------

    /// Handle an outbound request
    #[instrument(name = "handle_outbound_req", skip_all, fields(peer = %peer))]
    pub(crate) async fn handle_outbound_req(
        &self,
        peer: PeerId,
        req: GossipRequest,
        chan: Option<NetworkResponseChannel>,
    ) -> Result<(), NetworkManagerError> {
        set_parent_span_from_context(&req.tracing_headers());

        // Authenticate the request
        let key = self.cluster_key;
        let req_body = tokio::task::spawn_blocking(move || {
            AuthenticatedGossipRequest::new_with_body(req, &key)
        })
        .await
        .unwrap();

        self.send_behavior(BehaviorJob::SendReq(peer, req_body, chan))
    }

    /// Handle an outbound response
    #[instrument(name = "handle_outbound_resp", skip_all)]
    pub(crate) async fn handle_outbound_resp(
        &self,
        resp: GossipResponse,
        chan: ResponseChannel<AuthenticatedGossipResponse>,
    ) -> Result<(), NetworkManagerError> {
        set_parent_span_from_context(&resp.tracing_headers());

        // Authenticate the response
        let key = self.cluster_key;
        let authenticate_resp = tokio::task::spawn_blocking(move || {
            AuthenticatedGossipResponse::new_with_body(resp, &key)
        })
        .await
        .unwrap();

        self.send_behavior(BehaviorJob::SendResp(chan, authenticate_resp))
    }
}
