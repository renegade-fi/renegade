//! Groups message definitions for cluster management, mostly pubsub

use libp2p::Multiaddr;
use serde::{Deserialize, Serialize};

use crate::{
    gossip::types::{ClusterId, WrappedPeerId},
    state::Wallet,
};

/// The topic prefix for the cluster management pubsub topic
///
/// The actual topic name will have the cluster ID postfixed; i.e.
///     cluster-management-{cluster_id}
pub const CLUSTER_MANAGEMENT_TOPIC_PREFIX: &str = "cluster-management";

/// Repesents a pubsub message broadcast when a node joins a cluster
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClusterJoinMessage {
    /// The ID of the cluster being joined
    pub cluster_id: ClusterId,
    /// The peer ID of the node joining the cluster
    pub peer_id: WrappedPeerId,
    /// The address that the new peer can be dialed at
    pub addr: Multiaddr,
}

impl From<&ClusterJoinMessage> for Vec<u8> {
    fn from(message: &ClusterJoinMessage) -> Self {
        serde_json::to_vec(&message).unwrap()
    }
}

/// A message asking a peer to replicate a set of wallets
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplicateMessage {
    /// The wallets needing replication
    pub wallets: Vec<Wallet>,
}
