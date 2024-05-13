//! The network manager handles lower level interaction with the p2p network
mod behavior;
mod control_directives;
mod identify;
mod pubsub;
mod request_response;

use common::{
    default_wrapper::{DefaultOption, DefaultWrapper},
    new_async_shared,
    types::{gossip::WrappedPeerId, CancelChannel},
    AsyncShared,
};
use ed25519_dalek::Keypair as SigKeypair;
use futures::StreamExt;
use gossip_api::pubsub::PubsubMessage;
use job_types::{
    gossip_server::GossipServerQueue,
    handshake_manager::HandshakeManagerQueue,
    network_manager::{NetworkManagerJob, NetworkManagerReceiver},
};
use libp2p::{
    gossipsub::Event as GossipsubEvent, multiaddr::Protocol,
    request_response::Event as RequestResponseEvent, swarm::SwarmEvent, Multiaddr, Swarm,
};
use state::State;
use tracing::{error, info};

use std::sync::{atomic::AtomicBool, Arc};

use self::behavior::{new_behavior_queue, BehaviorReceiver, BehaviorSender};

use super::{
    composed_protocol::{ComposedNetworkBehavior, ComposedProtocolEvent},
    error::NetworkManagerError,
};

/// Occurs when a peer cannot be dialed because their address is not indexed in
/// the network behavior
const ERR_NO_KNOWN_ADDR: &str = "no known address for peer";
/// Error emitted when brokering an MPC network with a peer fails
const ERR_BROKER_MPC_NET: &str = "failed to broker MPC network";

/// The multiaddr protocol of the transport in libp2p
const TRANSPORT_PROTOCOL_NAME: &str = "udp";

// -----------
// | Helpers |
// -----------

/// Replace the tcp port in a multiaddr with the given port
pub fn replace_port(multiaddr: &mut Multiaddr, port: u16) {
    // Find the index of the transport in the multiaddr
    let mut index = None;
    for (i, protocol) in multiaddr.protocol_stack().enumerate() {
        if protocol == TRANSPORT_PROTOCOL_NAME {
            index = Some(i);
            break;
        }
    }

    match index {
        Some(transport_index) => {
            *multiaddr = multiaddr.replace(transport_index, |_| Some(Protocol::Udp(port))).unwrap();
        },
        None => *multiaddr = multiaddr.clone().with(Protocol::Udp(port)),
    }
}

// ------------
// | Executor |
// ------------

/// Represents a pubsub message that is buffered during the gossip warmup period
#[derive(Clone, Debug)]
struct BufferedPubsubMessage {
    /// The topic this message should be pushed onto
    pub topic: String,
    /// The underlying message that should be forwarded to the network
    pub message: PubsubMessage,
}

/// The executor abstraction runs in a thread separately from the network
/// manager
///
/// This allows the thread to take ownership of the executor object and perform
/// object-oriented operations while allowing the network manager ownership to
/// be held by the coordinator thread
#[derive(Clone)]
pub(super) struct NetworkManagerExecutor {
    /// The local port listened on
    p2p_port: u16,
    /// The peer ID of the local node
    local_peer_id: WrappedPeerId,
    /// The local cluster's keypair, used to sign and authenticate requests
    cluster_key: Arc<SigKeypair>,
    /// Whether or not to allow peer discovery on the local node
    allow_local: bool,
    /// Whether the network manager has discovered the local peer's public,
    /// dialable address via `Identify` already
    discovered_identity: Arc<AtomicBool>,
    /// Whether or not the warmup period has already elapsed
    warmup_finished: Arc<AtomicBool>,
    /// The messages buffered during the warmup period
    warmup_buffer: AsyncShared<Vec<BufferedPubsubMessage>>,
    /// The behavior channel receiver, used to sequence access to the underlying
    /// swarm
    behavior_rx: DefaultOption<BehaviorReceiver>,
    /// The behavior channel sender, used to send behaviors directly to the
    /// swarm from within the network manager's job handlers
    behavior_tx: BehaviorSender,
    /// The channel to receive outbound requests on from other workers
    ///
    /// The runtime driver thread takes ownership of this channel via `take` in
    /// the execution loop
    job_channel: DefaultOption<NetworkManagerReceiver>,
    /// The sender for the gossip server's work queue
    gossip_work_queue: GossipServerQueue,
    /// The sender for the handshake manager's work queue
    handshake_work_queue: HandshakeManagerQueue,
    /// A reference to the relayer-global state
    global_state: State,
    /// The cancel channel that the coordinator thread may use to cancel this
    /// worker
    cancel: DefaultWrapper<Option<CancelChannel>>,
}

impl NetworkManagerExecutor {
    /// Create a new executor
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        p2p_port: u16,
        local_peer_id: WrappedPeerId,
        allow_local: bool,
        cluster_key: SigKeypair,
        job_channel: NetworkManagerReceiver,
        gossip_work_queue: GossipServerQueue,
        handshake_work_queue: HandshakeManagerQueue,
        global_state: State,
        cancel: CancelChannel,
    ) -> Self {
        let (behavior_tx, behavior_rx) = new_behavior_queue();
        Self {
            p2p_port,
            local_peer_id,
            allow_local,
            cluster_key: Arc::new(cluster_key),
            discovered_identity: Arc::new(AtomicBool::new(false)),
            warmup_finished: Arc::new(AtomicBool::new(false)),
            warmup_buffer: new_async_shared(Vec::new()),
            behavior_rx: DefaultWrapper::new(Some(behavior_rx)),
            behavior_tx,
            job_channel: DefaultWrapper::new(Some(job_channel)),
            gossip_work_queue,
            handshake_work_queue,
            global_state,
            cancel: DefaultWrapper::new(Some(cancel)),
        }
    }

    /// The main loop in which the worker thread processes requests
    /// The worker handles two types of events:
    ///      1. Events from the network; which it dispatches to appropriate
    ///         handler threads
    ///      2. Events from workers to be sent over the network
    /// It handles these in the tokio select! macro below
    pub async fn executor_loop(
        mut self,
        mut swarm: Swarm<ComposedNetworkBehavior>,
    ) -> NetworkManagerError {
        info!("Starting executor loop for network manager...");
        let mut cancel_channel = self.cancel.take().unwrap();
        let mut job_channel = self.job_channel.take().unwrap();
        let mut behavior_channel = self.behavior_rx.take().unwrap();

        loop {
            tokio::select! {
                // Handle behavior requests from inside the worker
                Some(behavior_request) = behavior_channel.recv() => {
                    if let Err(err) = self.handle_behavior_job(behavior_request, &mut swarm).await {
                        error!("Error handling behavior job: {err}");
                    }
                },

                // Handle network requests from worker components of the relayer
                Some(job) = job_channel.recv() => {
                    // Forward the message
                    let this = self.clone();
                    tokio::spawn(async move {
                        if let Err(err) = this.handle_job(job).await {
                            error!("Error sending outbound message: {err}");
                        }
                    });
                },

                // Handle network events and dispatch
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::Behaviour(event) => {
                            let this = self.clone();
                            tokio::spawn(async move {
                                if let Err(err) = this.handle_inbound_message(event).await {
                                    info!("error in network manager: {:?}", err);
                                }
                            });
                        },
                        SwarmEvent::NewListenAddr { address, .. } => {
                            info!("Listening on {}/p2p/{}\n", address, self.local_peer_id);
                        },
                        // This catchall may be enabled for fine-grained libp2p introspection
                        x => { info!("Unhandled swarm event: {:?}", x) }
                    }
                }

                // Handle a cancel signal from the coordinator
                _ = cancel_channel.changed() => {
                    return NetworkManagerError::Cancelled("received cancel signal".to_string())
                }
            }
        }
    }

    /// Handles a network event from the relayer's protocol
    async fn handle_inbound_message(
        &self,
        message: ComposedProtocolEvent,
    ) -> Result<(), NetworkManagerError> {
        match message {
            ComposedProtocolEvent::RequestResponse(request_response) => {
                if let RequestResponseEvent::Message { peer, message, .. } = request_response {
                    self.handle_inbound_request_response_message(peer, message)?;
                }

                Ok(())
            },
            ComposedProtocolEvent::PubSub(msg) => {
                if let GossipsubEvent::Message { message, .. } = msg {
                    self.handle_inbound_pubsub_message(message)?;
                }

                Ok(())
            },
            // KAD events do nothing for now, routing tables are automatically updated by libp2p
            ComposedProtocolEvent::Kademlia(_) => Ok(()),
            ComposedProtocolEvent::Identify(e) => self.handle_identify_event(e).await,
        }
    }

    /// Handle a job originating from elsewhere in the local node
    async fn handle_job(&self, job: NetworkManagerJob) -> Result<(), NetworkManagerError> {
        match job {
            NetworkManagerJob::Pubsub(topic, msg) => self.forward_outbound_pubsub(topic, msg).await,
            NetworkManagerJob::Request(peer, req, chan) => {
                self.handle_outbound_req(peer.inner(), req, chan)
            },
            NetworkManagerJob::Response(resp, chan) => self.handle_outbound_resp(resp, chan),
            NetworkManagerJob::Internal(cmd) => self.handle_control_directive(cmd).await,
        }
    }
}

#[cfg(test)]
mod test {
    use super::replace_port;
    use libp2p::Multiaddr;

    /// Tests the helper that replaces the transport port in a multiaddr
    #[test]
    fn test_replace_port() {
        let mut addr: Multiaddr =
            "/ip4/127.0.0.1/udp/8000/quic-v1/p2p/12D3KooWKKahCLvwJnN4V7aCuzxcrtir58bSqre6qCB6Tjp9WVRu".parse().unwrap();
        replace_port(&mut addr, 9000);

        assert_eq!(
            addr.to_string(),
            "/ip4/127.0.0.1/udp/9000/quic-v1/p2p/12D3KooWKKahCLvwJnN4V7aCuzxcrtir58bSqre6qCB6Tjp9WVRu"
        );
    }
}
