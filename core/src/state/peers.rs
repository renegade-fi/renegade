//! Groups concurrent safe type definitions for indexing peers in the network

use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    sync::{RwLockReadGuard, RwLockWriteGuard},
    time::{SystemTime, UNIX_EPOCH},
};

use itertools::Itertools;
use termion::color;

use crate::gossip::types::{PeerInfo, WrappedPeerId};

use super::{new_shared, Shared};

/// The error message to panic with when a peer's lock has been poisoned
const ERR_PEER_POISONED: &str = "peer lock poisoned";

/// An index over known peers in the network
#[derive(Debug)]
pub struct PeerIndex {
    /// The peer ID of the local peer
    peer_id: WrappedPeerId,
    /// A mapping from peer ID to information about the peer
    peer_map: HashMap<WrappedPeerId, Shared<PeerInfo>>,
}

impl PeerIndex {
    /// Create a new peer index
    pub fn new(peer_id: WrappedPeerId) -> Self {
        Self {
            peer_id,
            peer_map: HashMap::new(),
        }
    }

    // -----------
    // | Locking |
    // -----------

    /// Acquire a read lock on a peer's info
    pub fn read_peer(&self, peer_id: &WrappedPeerId) -> Option<RwLockReadGuard<PeerInfo>> {
        self.peer_map
            .get(peer_id)
            .map(|peer_info| peer_info.read().expect(ERR_PEER_POISONED))
    }

    /// Acquire a write lock on a peer's info
    pub fn write_peer(&self, peer_id: &WrappedPeerId) -> Option<RwLockWriteGuard<PeerInfo>> {
        self.peer_map
            .get(peer_id)
            .map(|peer_info| peer_info.write().expect(ERR_PEER_POISONED))
    }

    // -----------
    // | Getters |
    // -----------

    /// Returns the number of peers in the index
    pub fn len(&self) -> usize {
        self.peer_map.len()
    }

    /// Returns whether the given peer is already indexed by the peer index
    pub fn contains_peer(&self, peer_id: &WrappedPeerId) -> bool {
        self.peer_map.contains_key(peer_id)
    }

    /// Return an nth index into an iterator formed over the hashmap
    pub fn nth(&self, index: usize) -> Option<RwLockReadGuard<PeerInfo>> {
        Some(
            self.peer_map
                .iter()
                .nth(index)?
                .1
                .read()
                .expect(ERR_PEER_POISONED),
        )
    }

    /// Returns a list of known peer IDs
    pub fn get_all_peer_ids(&self) -> Vec<WrappedPeerId> {
        self.peer_map.keys().cloned().collect_vec()
    }

    /// Return a mapping from peer ID to the peer's info
    ///
    /// This is constructed when the heartbeat message is constructed and sent to
    /// heartbeat peers
    pub fn get_info_map(&self) -> HashMap<WrappedPeerId, PeerInfo> {
        let mut res = HashMap::new();
        for (peer_id, info) in self.peer_map.iter() {
            res.insert(*peer_id, info.read().expect(ERR_PEER_POISONED).clone());
        }

        res
    }

    // -----------
    // | Setters |
    // -----------

    /// Add a peer to the peer index
    pub fn add_peer(&mut self, peer_info: PeerInfo) {
        if let Entry::Vacant(e) = self.peer_map.entry(peer_info.get_peer_id()) {
            e.insert(new_shared(peer_info));
        }
    }

    /// Remove a peer from the index
    pub fn remove_peer(&mut self, peer_id: &WrappedPeerId) -> Option<PeerInfo> {
        let entry = self
            .peer_map
            .remove(peer_id)?
            .read()
            .expect(ERR_PEER_POISONED)
            .clone();
        Some(entry)
    }

    /// Record a successful heartbeat for a peer
    pub fn record_heartbeat(&self, peer_id: &WrappedPeerId) {
        if let Some(peer_info_guard) = self.write_peer(peer_id) {
            peer_info_guard.successful_heartbeat();
        }
    }
}

/// Debug implementation used for printing known peer state when the local node is in debug mode
impl Display for PeerIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("negative timestamp")
            .as_secs();
        for (peer_id, info) in self.peer_map.iter() {
            let peer_info = info.read().expect(ERR_PEER_POISONED);
            let last_heartbeat_elapsed = if peer_id.ne(&self.peer_id) {
                (now - peer_info.get_last_heartbeat()) * 1000
            } else {
                0
            };

            f.write_fmt(format_args!(
                "\t\t- {}{}{}: \n\t\t\t{}last_heartbeat{}: {:?}ms \n\t\t\t{}cluster_id{}: {:?} }}\n\n",
                color::Fg(color::LightYellow),
                peer_id.0,
                color::Fg(color::Reset),
                color::Fg(color::Blue),
                color::Fg(color::Reset),
                last_heartbeat_elapsed,
                color::Fg(color::Blue),
                color::Fg(color::Reset),
                peer_info.get_cluster_id(),
            ))?;
        }

        Ok(())
    }
}
