//! API types for network info requests
use common::types::{chain::Chain, gossip::PeerInfo as IndexedPeerInfo};
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// The network topology
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Network {
    /// Identifier, e.g. "goerli"
    pub id: String,
    /// The list of clusters known to the local peer
    pub clusters: Vec<Cluster>,
}

impl Network {
    /// Create a network from a map of cluster ID to peer IDs
    pub fn from_cluster_peer_map(chain: Chain, clusters: HashMap<String, Vec<Peer>>) -> Self {
        let mut network_clusters = Vec::with_capacity(clusters.len());
        for (cluster_id, peers) in clusters.into_iter() {
            network_clusters.push(Cluster { id: cluster_id, peers });
        }

        let id = chain.to_string();
        Self { id, clusters: network_clusters }
    }
}

/// A cluster of peers, in the security model a cluster is assumed to be
/// controlled by a single actor
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cluster {
    /// Identifier
    pub id: String,
    /// The list of peers known to be members of the cluster
    pub peers: Vec<Peer>,
}

/// A peer in the network known to the local node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Peer {
    /// Identifier
    pub id: String,
    /// The ID of the cluster this peer belongs to
    pub cluster_id: String,
    /// The dialable, libp2p address of the peer
    pub addr: String,
    /// Whether or not the peer is believed to be the raft leader for its
    /// cluster
    ///
    /// For remote clusters, this will always be false, as a local peer will not
    /// generally have visibility into remote raft state
    pub is_leader: bool,
}

impl From<IndexedPeerInfo> for Peer {
    fn from(peer_info: IndexedPeerInfo) -> Self {
        Self {
            id: peer_info.get_peer_id().to_string(),
            cluster_id: peer_info.get_cluster_id().to_string(),
            addr: peer_info.get_addr().to_string(),
            is_leader: false,
        }
    }
}
