//! Groups message definitions for cluster management, mostly pubsub

use serde::{Deserialize, Serialize};

use crate::gossip::types::{ClusterId, WrappedPeerId};

/// An authentication challenge that the joining node signs with the cluster
/// private key in order to prove it is authorized to join the cluster
pub const CLUSTER_JOIN_CHALLENGE_DIGEST: &str = "join cluster";

/// Repesents a pubsub message broadcast when a node joins a cluster
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClusterJoinMessage {
    /// The ID of the cluster being joined
    pub cluster_id: ClusterId,
    /// The ID of the node joining the cluster
    pub node_id: WrappedPeerId,
    /// The result of the auth challenge, a signature of the challenge constant
    pub auth_challenge: Vec<u8>,
}
