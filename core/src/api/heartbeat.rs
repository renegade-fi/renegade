//! Groups API definitions for heartbeat requests and responses

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    gossip::types::{PeerInfo, WrappedPeerId},
    state::{
        wallet::{WalletIdentifier, WalletMetadata},
        ClusterMetadata,
    },
};

/// Defines the heartbeat message, both request and response take
/// on this message format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatMessage {
    /// The list of wallets managed by the sending relayer
    pub managed_wallets: HashMap<WalletIdentifier, WalletMetadata>,
    /// The set of peers known to the sending relayer
    /// PeerID is converted to string for serialization
    pub known_peers: HashMap<String, PeerInfo>,
    /// The metadata that the local peer has about its own cluster
    pub cluster_metadata: ClusterMetadata,
}

/// Defines a request to bootstrap the cluster state from the recipient
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BootstrapRequest {
    /// The requester's peer ID
    pub peer_id: WrappedPeerId,
}
