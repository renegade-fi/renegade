//! Cluster communications broadcast via Pubsub

use serde::{Deserialize, Serialize};
use types_gossip::{ClusterId, WrappedPeerId};

/// A message from one cluster peer to the rest indicating cluster management
/// hints
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClusterManagementMessage {
    /// The cluster ID of the sender
    pub cluster_id: ClusterId,
    /// The type of the message
    pub message_type: ClusterManagementMessageType,
}

/// Represents a message containing cluster management information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ClusterManagementMessageType {
    /// Propose a peer expiry to the cluster
    ///
    /// Peers will check the last heartbeat they received from the expiry
    /// candidate. If it is within some threshold they will reject the expiry.
    /// If no rejection is seen in a reasonable amount of time, the peer will
    /// be removed from the cluster
    ProposeExpiry(WrappedPeerId),
    /// Reject a peer expiry proposal
    ///
    /// Peers will check the last heartbeat they received from the expiry
    /// candidate. If it is within some threshold they will reject the expiry.
    /// If no rejection is seen in a reasonable amount of time, the peer will
    /// be removed from the cluster
    RejectExpiry {
        /// The peer id of the node that is proposing to expire
        peer_id: WrappedPeerId,
        /// The timestamp of the last heartbeat the sender received from the
        /// expiry candidate
        last_heartbeat: u64,
    },
}
