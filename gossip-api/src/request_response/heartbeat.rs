//! Groups API definitions for heartbeat requests and responses

use common::types::{
    gossip::{PeerInfo, WrappedPeerId},
    wallet::OrderIdentifier,
};

use serde::{Deserialize, Serialize};

/// Defines the heartbeat message, both request and response take
/// on this message format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatMessage {
    /// The list of peer IDs known to the sending node
    pub known_peers: Vec<WrappedPeerId>,
    /// The list of orders known to the sending node
    pub known_orders: Vec<OrderIdentifier>,
    /// The peer ID of the sending node
    pub self_id: WrappedPeerId,
}

/// Defines a request to bootstrap the cluster state from the recipient
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BootstrapRequest {
    /// The requester's peer ID
    pub peer_info: PeerInfo,
}

/// Defines a request for peer info from the recipient
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfoRequest {
    /// The peer ids that the requester wants info for
    pub peer_ids: Vec<WrappedPeerId>,
}

/// Defines a response to a request for peer info
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfoResponse {
    /// The peer info for the requested peers
    pub peer_info: Vec<PeerInfo>,
}
