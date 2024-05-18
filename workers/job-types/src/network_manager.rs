//! Job types for the network manager

use common::types::{gossip::WrappedPeerId, handshake::ConnectionRole};
use gossip_api::{
    pubsub::PubsubMessage,
    request_response::{AuthenticatedGossipResponse, GossipRequest, GossipResponse},
};
use libp2p::request_response::ResponseChannel;
use libp2p_core::Multiaddr;
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedSender as TokioSender},
    oneshot::{channel as oneshot_channel, Receiver as OneshotReceiver, Sender as OneshotSender},
};
use util::metered_channels::MeteredTokioReceiver;
use uuid::Uuid;

/// The name of the network manager queue, used to label queue length metrics
const NETWORK_MANAGER_QUEUE_NAME: &str = "network_manager";

/// The task queue type for the network manager
pub type NetworkManagerQueue = TokioSender<NetworkManagerJob>;
/// The task queue receiver type for the network manager
pub type NetworkManagerReceiver = MeteredTokioReceiver<NetworkManagerJob>;
/// The channel type on which the network manager forwards a response to a
/// particular request
pub type NetworkResponseChannel = OneshotSender<GossipResponse>;
/// The channel type a worker may receive a message response from the network
/// manager
pub type NetworkResponseReceiver = OneshotReceiver<GossipResponse>;

/// Create a new network manager queue and receiver
pub fn new_network_manager_queue() -> (NetworkManagerQueue, NetworkManagerReceiver) {
    let (send, recv) = unbounded_channel();
    (send, MeteredTokioReceiver::new(recv, NETWORK_MANAGER_QUEUE_NAME))
}
/// Create a new response channel for a request
pub fn new_response_channel() -> (NetworkResponseChannel, NetworkResponseReceiver) {
    oneshot_channel()
}

/// The job type for the network manager
#[derive(Debug)]
pub enum NetworkManagerJob {
    /// Send an outbound pubsub message
    ///
    /// The first field is the topic, the second is the message body
    Pubsub(String, PubsubMessage),
    /// Send a gossip request
    ///
    /// Optionally, the sending worker may specify a channel to receive the
    /// corresponding gossip response on
    Request(WrappedPeerId, GossipRequest, Option<NetworkResponseChannel>),
    /// Send a gossip response
    Response(GossipResponse, ResponseChannel<AuthenticatedGossipResponse>),
    /// An internal networking directive
    Internal(NetworkManagerControlSignal),
}

impl NetworkManagerJob {
    /// Construct a new pubsub message
    pub fn pubsub(topic: String, msg: PubsubMessage) -> Self {
        Self::Pubsub(topic, msg)
    }

    /// Construct a new gossip request
    pub fn request(peer_id: WrappedPeerId, request: GossipRequest) -> Self {
        Self::Request(peer_id, request, None)
    }

    /// Construct a new gossip request with a response channel
    pub fn request_with_response(
        peer_id: WrappedPeerId,
        request: GossipRequest,
    ) -> (Self, NetworkResponseReceiver) {
        let (send, recv) = new_response_channel();
        (Self::Request(peer_id, request, Some(send)), recv)
    }

    /// Construct a new gossip response
    pub fn response(
        response: GossipResponse,
        channel: ResponseChannel<AuthenticatedGossipResponse>,
    ) -> Self {
        Self::Response(response, channel)
    }

    /// Construct a new internal network manager control signal
    pub fn internal(control_signal: NetworkManagerControlSignal) -> Self {
        Self::Internal(control_signal)
    }
}

/// A message type send from a worker to the network manager itself to
/// explicitly control or signal information
#[derive(Clone, Debug)]
pub enum NetworkManagerControlSignal {
    /// A command signalling to the network manager to open up a QUIC connection
    /// and build an MPC network instance to handshake over
    BrokerMpcNet {
        /// The ID of the ongoing handshake
        request_id: Uuid,
        /// The ID of the peer to dial
        peer_id: WrappedPeerId,
        /// The port that the peer has exposed to dial on
        peer_port: u16,
        /// The local port that should be used to accept the stream
        local_port: u16,
        /// The role of the local node in the connection setup
        local_role: ConnectionRole,
    },
    /// A command signalling to the network manager that a new node has been
    /// discovered at the application level. The network manager should register
    /// this node with the KDHT and propagate this change
    NewAddr {
        /// The PeerID to which the new address belongs
        peer_id: WrappedPeerId,
        /// The new address
        address: Multiaddr,
    },
    /// A command signalling to the network manager that a peer has been expired
    /// and it should be removed from the Kademlia DHT
    PeerExpired {
        /// The PeerID of the expired Peer
        peer_id: WrappedPeerId,
    },
    /// A command informing the network manager that the gossip protocol has
    /// warmed up in the network
    ///
    /// The network manager delays Pubsub messages (buffering them) until warmup
    /// has elapsed to allow the libp2p swarm time to build connections that
    /// the gossipsub protocol may graft to
    GossipWarmupComplete,
}
