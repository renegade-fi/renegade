//! Groups concurrent safe type definitions for indexing peers in the network

use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    sync::{RwLockReadGuard, RwLockWriteGuard},
    time::{SystemTime, UNIX_EPOCH},
};

use itertools::Itertools;
use rand::{thread_rng, Rng};
use termion::color;

use crate::gossip::types::{ClusterId, PeerInfo, WrappedPeerId};

use super::{new_shared, Shared};

/// Error message emitted when a cluster peer list lock is poisoned
const ERR_CLUSTER_LIST_POISONED: &str = "cluster peer list poisoned";
/// The error message to panic with when a peer's lock has been poisoned
const ERR_PEER_POISONED: &str = "peer lock poisoned";

/// An index over known peers in the network
#[derive(Debug)]
pub struct PeerIndex {
    /// The peer ID of the local peer
    peer_id: WrappedPeerId,
    /// A mapping from peer ID to information about the peer
    peer_map: HashMap<WrappedPeerId, Shared<PeerInfo>>,
    /// A mapping from cluster ID to a list of known peers in the cluster
    cluster_peers: HashMap<ClusterId, Shared<HashSet<WrappedPeerId>>>,
}

impl PeerIndex {
    /// Create a new peer index
    pub fn new(peer_id: WrappedPeerId) -> Self {
        Self {
            peer_id,
            peer_map: HashMap::new(),
            cluster_peers: HashMap::new(),
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

    /// Acquires a read lock on a cluster's peer list
    pub fn read_cluster_peers(
        &self,
        cluster_id: &ClusterId,
    ) -> Option<RwLockReadGuard<HashSet<WrappedPeerId>>> {
        self.cluster_peers
            .get(cluster_id)
            .map(|cluster| cluster.read().expect(ERR_CLUSTER_LIST_POISONED))
    }

    /// Acquire a write lock on a peer's info
    pub fn write_peer(&self, peer_id: &WrappedPeerId) -> Option<RwLockWriteGuard<PeerInfo>> {
        self.peer_map
            .get(peer_id)
            .map(|peer_info| peer_info.write().expect(ERR_PEER_POISONED))
    }

    /// Acquire a write lock on a cluster's peer list
    pub fn write_cluster_peers(
        &self,
        cluster_id: &ClusterId,
    ) -> Option<RwLockWriteGuard<HashSet<WrappedPeerId>>> {
        self.cluster_peers
            .get(cluster_id)
            .map(|cluster| cluster.write().expect(ERR_CLUSTER_LIST_POISONED))
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

    /// Returns a list of all cluster peers
    pub fn get_all_cluster_peers(&self, cluster_id: &ClusterId) -> Vec<WrappedPeerId> {
        self.read_cluster_peers(cluster_id)
            .map(|peers| peers.iter().cloned().collect_vec())
            .unwrap_or_default()
    }

    /// Returns a random cluster peer for the given cluster
    pub fn sample_cluster_peer(&self, cluster_id: &ClusterId) -> Option<WrappedPeerId> {
        let mut rng = thread_rng();
        let cluster_peers = self.read_cluster_peers(cluster_id)?;

        // Choose a random value from the set of peers
        if cluster_peers.is_empty() {
            return None;
        }

        let random_index = rng.gen_range(0..cluster_peers.len());
        cluster_peers.iter().nth(random_index).cloned()
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
        // Add the peer to the list of known peers in its cluster
        let peer_cluster_record = self
            .cluster_peers
            .entry(peer_info.get_cluster_id())
            .or_insert_with(|| new_shared(HashSet::new()));
        peer_cluster_record
            .write()
            .expect(ERR_CLUSTER_LIST_POISONED)
            .insert(peer_info.get_peer_id());

        // Add the peer only if it does not already exist
        if let Entry::Vacant(e) = self.peer_map.entry(peer_info.get_peer_id()) {
            e.insert(new_shared(peer_info));
        }
    }

    /// Remove a peer from the index
    pub fn remove_peer(&mut self, peer_id: &WrappedPeerId) -> Option<PeerInfo> {
        // Remove from the peer info index
        let entry = self
            .peer_map
            .remove(peer_id)?
            .read()
            .expect(ERR_PEER_POISONED)
            .clone();

        // Remove from the peer's cluster list
        self.write_cluster_peers(&entry.get_cluster_id())
            .unwrap()
            .remove(&entry.get_peer_id());

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
