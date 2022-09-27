use std::collections::HashMap;

use libp2p::{request_response::ResponseChannel, Multiaddr};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    gossip::types::{PeerInfo, WrappedPeerId},
    state::{RelayerState, WalletMetadata},
};

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

// Defines the heartbeat message, both request and response take
// on this message format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatMessage {
    // The list of wallets managed by the sending relayer
    pub managed_wallets: HashMap<Uuid, WalletMetadata>,
    // The set of peers known to the sending relayer
    // PeerID is converted to string for serialization
    pub known_peers: HashMap<String, PeerInfo>,
}

/**
 * Implements the derivation from global state to heartbeat message.
 * The state primitive passed around to workers is of type GlobalRelayerState;
 * this is an Arc<RwLock> wrapper around RelayerState. The caller of this cast
 * should handle locking the object
 */
impl From<&RelayerState> for HeartbeatMessage {
    fn from(state: &RelayerState) -> Self {
        let mut managed_wallet_metadata: HashMap<Uuid, WalletMetadata> = HashMap::new();
        for (wallet_id, wallet) in state.managed_wallets.iter() {
            managed_wallet_metadata.insert(*wallet_id, wallet.metadata.clone());
        }

        // Convert peer info keys to strings for serialization/deserialization
        let mut known_peers: HashMap<String, PeerInfo> = HashMap::new();
        for (peer_id, peer_info) in state.known_peers.iter() {
            known_peers.insert(peer_id.to_string(), peer_info.clone());
        }

        HeartbeatMessage {
            managed_wallets: managed_wallet_metadata,
            known_peers,
        }
    }
}

// Represents a gossip message sent to initiate a handshake request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeMessage {
    // The handshake operation to perform
    pub operation: HandshakeOperation,
}

// Enumerates the different operations possible via handshake
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HandshakeOperation {
    Mpc,
}
