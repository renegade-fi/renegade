//! Groups API definitions for heartbeat requests and responses

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    gossip::types::PeerInfo,
    state::{ClusterMetadata, RelayerState, WalletMetadata},
};

/// Defines the heartbeat message, both request and response take
/// on this message format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatMessage {
    /// The list of wallets managed by the sending relayer
    pub managed_wallets: HashMap<Uuid, WalletMetadata>,
    /// The set of peers known to the sending relayer
    /// PeerID is converted to string for serialization
    pub known_peers: HashMap<String, PeerInfo>,
    /// The metadata that the local peer has about its own cluster
    pub cluster_metadata: ClusterMetadata,
}

/// The derivation from global state to heartbeat message
impl From<&RelayerState> for HeartbeatMessage {
    fn from(state: &RelayerState) -> Self {
        let mut managed_wallet_metadata: HashMap<Uuid, WalletMetadata> = HashMap::new();
        for (wallet_id, wallet) in state.read_managed_wallets().iter() {
            managed_wallet_metadata.insert(*wallet_id, wallet.metadata.clone());
        }

        // Convert peer info keys to strings for serialization/deserialization
        let mut known_peers = HashMap::new();
        for (peer_id, peer_info) in state.read_known_peers().iter() {
            known_peers.insert(peer_id.to_string(), peer_info.clone());
        }

        HeartbeatMessage {
            managed_wallets: managed_wallet_metadata,
            known_peers,
            cluster_metadata: state.read_cluster_metadata().clone(),
        }
    }
}
