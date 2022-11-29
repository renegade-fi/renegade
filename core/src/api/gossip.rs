//! Groups API definitions for standard gossip network requests/responses

use libp2p::{request_response::ResponseChannel, Multiaddr};
use serde::{Deserialize, Serialize};

use crate::gossip::types::WrappedPeerId;

use super::{handshake::HandshakeMessage, hearbeat::HeartbeatMessage};

/**
 * This file groups API related definitions for the relayer's libp2p protocol
 */

// Represents an outbound gossip message, either a request to a peer
// or a response to a peer's request
#[derive(Debug)]
pub enum GossipOutbound {
    // A generic request sent to the network manager for outbound delivery
    Request {
        peer_id: WrappedPeerId,
        message: GossipRequest,
    },
    // A generic response sent to the network manager for outbound delivery
    Response {
        channel: ResponseChannel<GossipResponse>,
        message: GossipResponse,
    },
    // A command signalling to the network manager that a new node has been
    // discovered at the application level. The network manager should register
    // this node with the KDHT and propagate this change
    NewAddr {
        peer_id: WrappedPeerId,
        address: Multiaddr,
    },
}

// Represents the message data passed via the network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipRequest {
    Heartbeat(HeartbeatMessage),
    Handshake(HandshakeMessage),
}

// Enumerates the possible response types for a gossip message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipResponse {
    Heartbeat(HeartbeatMessage),
    Handshake(),
}
