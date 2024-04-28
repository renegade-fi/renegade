//! API types for network info requests
use common::types::gossip::PeerInfo as IndexedPeerInfo;
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

/// Cast from a map of cluster ID to peer list to the `Cluster` API type
impl From<HashMap<String, Vec<Peer>>> for Network {
    fn from(cluster_membership: HashMap<String, Vec<Peer>>) -> Self {
        let mut clusters = Vec::with_capacity(cluster_membership.len());
        for (cluster_id, peers) in cluster_membership.into_iter() {
            clusters.push(Cluster { id: cluster_id, peers });
        }

        Self {
            // TODO: Make this not a constant
            id: "goerli".to_string(),
            clusters,
        }
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
}

impl From<IndexedPeerInfo> for Peer {
    fn from(peer_info: IndexedPeerInfo) -> Self {
        Self {
            id: peer_info.get_peer_id().to_string(),
            cluster_id: peer_info.get_cluster_id().to_string(),
            addr: peer_info.get_addr().to_string(),
        }
    }
}
