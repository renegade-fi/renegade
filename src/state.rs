use serde::{Serialize, Deserialize, };
use std::{
    collections::HashMap,
    sync::{Arc, RwLock}, str::FromStr
};

use crate::gossip::types::{PeerInfo, WrappedPeerId};


/**
 * This file groups type definitions and helpers around global state that 
 * is passed around throughout the code
 */

/**
 * Constants and Types
 */

// The ideal of peers that manage a given wallet in tandum
const TARGET_WALLET_REPLICAS: usize = 5;

// A type alias for the thread-safe relayer state
pub type GlobalRelayerState = Arc<RwLock<RelayerState>>;

/**
 * State objects
 * Use #[serde(skip)] to maintain private state
 */

#[derive(Debug, Serialize, Deserialize)]
// The top level object in the global state tree
pub struct RelayerState {
    // The list of wallets managed by the sending relayer
    pub managed_wallets: HashMap<uuid::Uuid, Wallet>,
    // The set of peers known to the sending relayer
    pub known_peers: HashMap<WrappedPeerId, PeerInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
// Represents a wallet managed by the local relayer
pub struct Wallet {
    // Wallet metadata; replicas, trusted peers, etc
    pub metadata: WalletMetadata,
    // Wallet id will eventually be replaced, for now it is UUID
    pub wallet_id: uuid::Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
// Metadata relevant to the wallet's network state
pub struct WalletMetadata {
    pub replicas: Vec<WrappedPeerId>,
}

impl RelayerState {
    pub fn initialize_global_state() -> GlobalRelayerState {
        let mut managed_wallets = HashMap::new();
        let wallet_id = uuid::Uuid::from_str("67e55044-10b1-426f-9247-bb680e5fe0c8").expect("error with UUID");
        let wal = Wallet {
            wallet_id,
            metadata: WalletMetadata { replicas: vec![] } 
        };
        managed_wallets.insert(uuid::Uuid::from_str("67e55044-10b1-426f-9247-bb680e5fe0c8").expect("err"), wal);
        Arc::new(
            RwLock::new(
                Self { 
                    managed_wallets: managed_wallets, 
                    known_peers: HashMap::new(),
                }
            )
        )
    }
}