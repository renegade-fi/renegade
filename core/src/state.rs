//! This file groups type definitions and helpers around global state that
//! is passed around throughout the code

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Arc, RwLock},
};

use crate::gossip::types::{ClusterId, PeerInfo, WrappedPeerId};

/**
 * Constants and Types
 */

/// A type alias for the thread-safe relayer state
pub type GlobalRelayerState = Arc<RwLock<RelayerState>>;

/**
 * State objects
 * Use #[serde(skip)] to maintain private state
 */

#[derive(Debug, Serialize, Deserialize)]
// The top level object in the global state tree
pub struct RelayerState {
    /// The libp2p peerID assigned to the localhost
    pub local_peer_id: Option<WrappedPeerId>,
    /// The cluster id of the local relayer
    pub local_cluster_id: ClusterId,
    /// The list of wallets managed by the sending relayer
    pub managed_wallets: HashMap<uuid::Uuid, Wallet>,
    /// The set of peers known to the sending relayer
    pub known_peers: HashMap<WrappedPeerId, PeerInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
// Represents a wallet managed by the local relayer
pub struct Wallet {
    /// Wallet metadata; replicas, trusted peers, etc
    pub metadata: WalletMetadata,
    /// Wallet id will eventually be replaced, for now it is UUID
    pub wallet_id: uuid::Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Metadata relevant to the wallet's network state
pub struct WalletMetadata {
    pub replicas: Vec<WrappedPeerId>,
}

impl RelayerState {
    pub fn initialize_global_state(
        managed_wallet_ids: Vec<String>,
        bootstrap_servers: Vec<PeerInfo>,
        cluster_id: ClusterId,
    ) -> GlobalRelayerState {
        // Setup initial wallets
        let mut managed_wallets = HashMap::new();
        for wallet_id in managed_wallet_ids.iter() {
            let wallet_id = uuid::Uuid::from_str(wallet_id).expect("could not parse wallet ID");
            let wal = Wallet {
                wallet_id,
                metadata: WalletMetadata { replicas: vec![] },
            };
            managed_wallets.insert(wallet_id, wal);
        }

        // Setup initial set of known peers to be the bootstrap servers
        let mut known_peers = HashMap::<WrappedPeerId, PeerInfo>::new();
        for server in bootstrap_servers.iter() {
            known_peers.insert(server.get_peer_id(), server.clone());
        }

        Arc::new(RwLock::new(Self {
            local_peer_id: None,
            managed_wallets,
            known_peers,
            local_cluster_id: cluster_id,
        }))
    }
}
