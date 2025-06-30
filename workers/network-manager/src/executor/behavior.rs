//! Handles jobs that should be forwarded directly to the libp2p behavior
//! underlying the swarm

use gossip_api::{
    pubsub::AuthenticatedPubsubMessage,
    request_response::{AuthenticatedGossipRequest, AuthenticatedGossipResponse},
};
use job_types::network_manager::NetworkResponseChannel;
use libp2p::{Multiaddr, PeerId, Swarm, gossipsub::Sha256Topic, request_response::ResponseChannel};
use libp2p_core::Endpoint;
use libp2p_swarm::{ConnectionId, NetworkBehaviour};
use tokio::sync::{
    mpsc::{UnboundedReceiver as TokioReceiver, UnboundedSender as TokioSender, unbounded_channel},
    oneshot,
};
use tracing::instrument;
use util::{err_str, telemetry::propagation::set_parent_span_from_context};

use crate::{composed_protocol::ComposedNetworkBehavior, error::NetworkManagerError};

use super::{ERR_NO_KNOWN_ADDR, NetworkManagerExecutor};

/// Error message emitted when a response fails to be sent
const ERR_SEND_INTERNAL: &str = "Failed to send internal worker response";
/// Error sending a response to a peer on the network
const ERR_SEND_RESPONSE: &str = "Failed to send response";

/// The queue sender type for behavior jobs
pub type BehaviorSender = TokioSender<BehaviorJob>;
/// The queue receiver type for behavior jobs
pub type BehaviorReceiver = TokioReceiver<BehaviorJob>;
/// Create a new behavior queue
pub fn new_behavior_queue() -> (BehaviorSender, BehaviorReceiver) {
    unbounded_channel()
}

/// The job type of behavior requests
pub enum BehaviorJob {
    // --- Messaging --- //
    /// Send an outbound request
    SendReq(PeerId, AuthenticatedGossipRequest, Option<NetworkResponseChannel>),
    /// Send an outbound response
    SendResp(ResponseChannel<AuthenticatedGossipResponse>, AuthenticatedGossipResponse),
    /// Send a pubsub message
    SendPubsub(Sha256Topic, AuthenticatedPubsubMessage),

    // --- KDHT --- //
    /// Add an address to the DHT
    AddAddress(PeerId, Multiaddr),
    /// Expire a peer
    RemovePeer(PeerId),

    // --- Address Lookup --- //
    /// Lookup known addresses for a peer and return on a channel
    ///
    /// Used when brokering an MPC network
    LookupAddr(PeerId, oneshot::Sender<Vec<Multiaddr>>),
}

impl NetworkManagerExecutor {
    /// Enqueue a behavior job from elsewhere in the network manager
    pub(crate) fn send_behavior(&self, job: BehaviorJob) -> Result<(), NetworkManagerError> {
        self.behavior_tx.send(job).map_err(err_str!(NetworkManagerError::EnqueueJob))
    }

    /// Handle a behavior job
    #[instrument(name = "handle_behavior_job", skip_all)]
    pub(crate) async fn handle_behavior_job(
        &mut self,
        job: BehaviorJob,
        swarm: &mut Swarm<ComposedNetworkBehavior>,
    ) -> Result<(), NetworkManagerError> {
        match job {
            BehaviorJob::SendReq(peer_id, req, chan) => {
                set_parent_span_from_context(&req.inner.tracing_headers());

                let rid = swarm.behaviour_mut().request_response.send_request(&peer_id, req);
                if let Some(chan) = chan {
                    self.response_waiters.insert(rid, chan).await;
                }

                Ok(())
            },
            BehaviorJob::SendResp(channel, resp) => {
                set_parent_span_from_context(&resp.inner.tracing_headers());

                swarm
                    .behaviour_mut()
                    .request_response
                    .send_response(channel, resp)
                    .map_err(|_| NetworkManagerError::Network(ERR_SEND_RESPONSE.to_string()))
            },
            BehaviorJob::SendPubsub(topic, msg) => swarm
                .behaviour_mut()
                .pubsub
                .publish(topic, msg)
                .map(|_| ())
                .map_err(err_str!(NetworkManagerError::Network)),
            BehaviorJob::AddAddress(peer_id, addr) => {
                swarm.behaviour_mut().kademlia_dht.add_address(&peer_id, addr);
                Ok(())
            },
            BehaviorJob::RemovePeer(peer_id) => {
                swarm.behaviour_mut().kademlia_dht.remove_peer(&peer_id);
                Ok(())
            },
            BehaviorJob::LookupAddr(peer_id, sender) => {
                let addr = swarm
                    .behaviour_mut()
                    .handle_pending_outbound_connection(
                        ConnectionId::new_unchecked(0),
                        Some(peer_id),
                        &[],
                        Endpoint::Dialer,
                    )
                    .map_err(|_| NetworkManagerError::Network(ERR_NO_KNOWN_ADDR.to_string()))?;

                sender
                    .send(addr)
                    .map_err(|_| NetworkManagerError::SendInternal(ERR_SEND_INTERNAL.to_string()))
            },
        }
    }
}
