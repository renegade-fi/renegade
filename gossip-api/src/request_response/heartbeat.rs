//! Groups API definitions for heartbeat requests and responses

use common::types::gossip::{PeerInfo, WrappedPeerId};
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Defines the heartbeat message, both request and response take
/// on this message format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatMessage {
    /// The set of peers known to the sending relayer
    pub known_peers: HashMap<WrappedPeerId, PeerInfo>,
}

/// Defines a request to bootstrap the cluster state from the recipient
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BootstrapRequest {
    /// The requester's peer ID
    pub peer_info: PeerInfo,
}
