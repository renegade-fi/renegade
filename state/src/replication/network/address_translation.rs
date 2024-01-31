//! Provides a primitive by which we translate between gossip peer IDs and
//! replication layer IDs

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use common::types::gossip::WrappedPeerId;
use fxhash::hash64 as fxhash64;

/// A translation map wrapped in a thread-safe container
pub type SharedPeerIdTranslationMap = Arc<RwLock<PeerIdTranslationMap>>;

/// A mapping from raft IDs to libp2p peer IDs used in gossip
#[derive(Default)]
pub struct PeerIdTranslationMap {
    /// The underlying mapping
    map: HashMap<u64, WrappedPeerId>,
}

impl PeerIdTranslationMap {
    /// Constructor
    pub fn new() -> Self {
        Self { map: HashMap::new() }
    }

    /// Insert a new peer ID
    pub fn insert(&mut self, peer_id: WrappedPeerId) {
        let raft_id = Self::get_raft_id(&peer_id);
        self.map.insert(raft_id, peer_id);
    }

    /// Get a peer ID from a raft ID
    pub fn get_peer_id(&self, raft_id: u64) -> Option<WrappedPeerId> {
        self.map.get(&raft_id).cloned()
    }

    /// Translate a peer ID to a raft ID
    ///
    /// We hash the underlying peer ID (a mulltihash of the public key) to get a
    /// raft peer ID
    pub fn get_raft_id(peer_id: &WrappedPeerId) -> u64 {
        fxhash64(&peer_id)
    }
}
