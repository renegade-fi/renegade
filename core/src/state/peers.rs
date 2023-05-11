//! Groups concurrent safe type definitions for indexing peers in the network

use itertools::Itertools;
use libp2p::Multiaddr;
use rand::{thread_rng, Rng};
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    fmt::Debug,
    mem,
};
use tokio::sync::{RwLockReadGuard, RwLockWriteGuard};
use tracing::log;

use crate::{
    gossip::types::{ClusterId, PeerInfo, WrappedPeerId},
    network_manager::manager::is_local_addr,
};

use super::{new_async_shared, AsyncShared};

/// An index over known peers in the network
#[derive(Debug)]
pub struct PeerIndex {
    /// Whether or not to allow peers on the localhost
    allow_local: bool,
    /// A mapping from peer ID to information about the peer
    peer_map: HashMap<WrappedPeerId, AsyncShared<PeerInfo>>,
    /// A mapping from cluster ID to a list of known peers in the cluster
    cluster_peers: HashMap<ClusterId, AsyncShared<HashSet<WrappedPeerId>>>,
}

impl PeerIndex {
    /// Create a new peer index
    pub fn new(allow_local: bool) -> Self {
        Self {
            allow_local,
            peer_map: HashMap::new(),
            cluster_peers: HashMap::new(),
        }
    }

    // -----------
    // | Locking |
    // -----------

    /// Acquire a read lock on a peer's info
    pub async fn read_peer(&self, peer_id: &WrappedPeerId) -> Option<RwLockReadGuard<PeerInfo>> {
        if let Some(peer_info) = self.peer_map.get(peer_id) {
            Some(peer_info.read().await)
        } else {
            None
        }
    }

    /// Acquires a read lock on a cluster's peer list
    pub async fn read_cluster_peers(
        &self,
        cluster_id: &ClusterId,
    ) -> Option<RwLockReadGuard<HashSet<WrappedPeerId>>> {
        if let Some(cluster) = self.cluster_peers.get(cluster_id) {
            Some(cluster.read().await)
        } else {
            None
        }
    }

    /// Acquire a write lock on a peer's info
    pub async fn write_peer(&self, peer_id: &WrappedPeerId) -> Option<RwLockWriteGuard<PeerInfo>> {
        if let Some(peer_info) = self.peer_map.get(peer_id) {
            Some(peer_info.write().await)
        } else {
            None
        }
    }

    /// Acquire a write lock on a cluster's peer list
    pub async fn write_cluster_peers(
        &self,
        cluster_id: &ClusterId,
    ) -> Option<RwLockWriteGuard<HashSet<WrappedPeerId>>> {
        if let Some(cluster) = self.cluster_peers.get(cluster_id) {
            Some(cluster.write().await)
        } else {
            None
        }
    }

    // -----------
    // | Getters |
    // -----------

    /// Returns the number of peers in the index
    pub fn len(&self) -> usize {
        self.peer_map.len()
    }

    /// Returns the info for a given peer
    pub async fn get_peer_info(&self, peer_id: &WrappedPeerId) -> Option<PeerInfo> {
        Some(self.peer_map.get(peer_id)?.read().await.clone())
    }

    /// Returns whether the given peer is already indexed by the peer index
    pub fn contains_peer(&self, peer_id: &WrappedPeerId) -> bool {
        self.peer_map.contains_key(peer_id)
    }

    /// Returns a list of all cluster peers
    pub async fn get_all_cluster_peers(&self, cluster_id: &ClusterId) -> Vec<WrappedPeerId> {
        if let Some(peers) = self.read_cluster_peers(cluster_id).await {
            peers.clone().into_iter().collect_vec()
        } else {
            Vec::new()
        }
    }

    /// Returns a random cluster peer for the given cluster
    pub async fn sample_cluster_peer(&self, cluster_id: &ClusterId) -> Option<WrappedPeerId> {
        let cluster_peers = self.read_cluster_peers(cluster_id).await?;

        // Choose a random value from the set of peers
        if cluster_peers.is_empty() {
            return None;
        }

        let mut rng = thread_rng();
        let random_index = rng.gen_range(0..cluster_peers.len());
        cluster_peers.iter().nth(random_index).cloned()
    }

    /// Return an nth index into an iterator formed over the hashmap
    pub async fn nth(&self, index: usize) -> Option<RwLockReadGuard<PeerInfo>> {
        Some(self.peer_map.iter().nth(index)?.1.read().await)
    }

    /// Returns a list of known peer IDs
    pub fn get_all_peer_ids(&self) -> Vec<WrappedPeerId> {
        self.peer_map.keys().cloned().collect_vec()
    }

    /// Return a mapping from peer ID to the peer's info
    ///
    /// This is constructed when the heartbeat message is constructed and sent to
    /// heartbeat peers
    pub async fn get_info_map(&self) -> HashMap<WrappedPeerId, PeerInfo> {
        let mut res = HashMap::new();
        for (peer_id, info) in self.peer_map.iter() {
            res.insert(*peer_id, info.read().await.clone());
        }

        res
    }

    // -----------
    // | Setters |
    // -----------

    /// Add a peer to the peer index
    ///
    /// Validates that the known address for the peer is dialable, i.e. not a local address
    pub async fn add_peer(&mut self, peer_info: PeerInfo) {
        // If the peer info specifies a local addr, skip adding the peer, it is not dialable
        if !self.allow_local && is_local_addr(&peer_info.addr) {
            log::info!("got peer info with un-dialable addr, skipping indexing");
            return;
        }

        self.add_peer_unchecked(peer_info).await;
    }

    /// Add a peer without validating that the given address is valid
    pub async fn add_peer_unchecked(&mut self, peer_info: PeerInfo) {
        // Add the peer to the list of known peers in its cluster
        let peer_cluster_record = self
            .cluster_peers
            .entry(peer_info.get_cluster_id())
            .or_insert_with(|| new_async_shared(HashSet::new()));
        peer_cluster_record
            .write()
            .await
            .insert(peer_info.get_peer_id());

        // Add the peer only if it does not already exist
        if let Entry::Vacant(e) = self.peer_map.entry(peer_info.get_peer_id()) {
            e.insert(new_async_shared(peer_info));
        }
    }

    /// Remove a peer from the index
    pub async fn remove_peer(&mut self, peer_id: &WrappedPeerId) -> Option<PeerInfo> {
        // Remove from the peer info index
        let entry = self.peer_map.remove(peer_id)?.read().await.clone();

        // Remove from the peer's cluster list
        self.write_cluster_peers(&entry.get_cluster_id())
            .await
            .unwrap()
            .remove(&entry.get_peer_id());

        Some(entry)
    }

    /// Update an address for a peer
    ///
    /// Returns the old address if one was found, otherwise `None`
    pub async fn update_peer_addr(
        &self,
        peer_id: &WrappedPeerId,
        new_addr: Multiaddr,
    ) -> Option<Multiaddr> {
        Some(mem::replace(
            &mut self.write_peer(peer_id).await?.addr,
            new_addr,
        ))
    }

    /// Record a successful heartbeat for a peer
    pub async fn record_heartbeat(&self, peer_id: &WrappedPeerId) {
        if let Some(peer_info_guard) = self.write_peer(peer_id).await {
            peer_info_guard.successful_heartbeat();
        }
    }
}
