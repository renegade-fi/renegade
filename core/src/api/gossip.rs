//! Groups API definitions for standard gossip network requests/responses

use libp2p::{request_response::ResponseChannel, Multiaddr};
use serde::{Deserialize, Serialize};

use crate::gossip::types::WrappedPeerId;

use super::{
    cluster_management::ClusterJoinMessage, handshake::HandshakeMessage, hearbeat::HeartbeatMessage,
};

/**
 * This file groups API related definitions for the relayer's libp2p protocol
 */

/// Represents an outbound gossip message, either a request to a peer
/// or a response to a peer's request
#[derive(Debug)]
pub enum GossipOutbound {
    /// A generic request sent to the network manager for outbound delivery
    Request {
        peer_id: WrappedPeerId,
        message: GossipRequest,
    },
    /// A generic response sent to the network manager for outbound delivery
    Response {
        channel: ResponseChannel<GossipResponse>,
        message: GossipResponse,
    },
    /// An outbound pubsub message to be flooded into the peer-to-peer network
    Pubsub {
        topic: String,
        message: PubsubMessage,
    },
    /// A command signalling to the network manager that a new node has been
    /// discovered at the application level. The network manager should register
    /// this node with the KDHT and propagate this change
    NewAddr {
        peer_id: WrappedPeerId,
        address: Multiaddr,
    },
}

/// Represents a request delivered point-to-point through the libp2p
/// request-response protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipRequest {
    Heartbeat(HeartbeatMessage),
    Handshake(HandshakeMessage),
}

/// Represents the possible response types for a request-response message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipResponse {
    Heartbeat(HeartbeatMessage),
    Handshake(),
}

/// Represents a pubsub message flooded through the network
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PubsubMessage {
    Join(ClusterJoinMessage),
}

/// Explicit byte serialization and deserialization
///
/// libp2p gossipsub interface expects a type that can be cast
/// to and from bytes
impl From<PubsubMessage> for Vec<u8> {
    fn from(message: PubsubMessage) -> Self {
        serde_json::to_vec(&message).unwrap()
    }
}

impl From<Vec<u8>> for PubsubMessage {
    fn from(buf: Vec<u8>) -> Self {
        serde_json::from_slice(&buf).unwrap()
    }
}
