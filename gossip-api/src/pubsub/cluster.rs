//! Cluster communications broadcast via Pubsub

use common::types::{gossip::ClusterId, wallet::OrderIdentifier};
use serde::{Deserialize, Serialize};

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
    /// A message to cluster peers indicating that the publisher has begun a
    /// handshake on the given order pair
    ///
    /// Recipients should place this order pair in an invisibility window and
    /// not schedule it for handshake until the invisibility period has
    /// elapsed and either resulted in a match or an error
    MatchInProgress(OrderIdentifier, OrderIdentifier),
    /// A cache synchronization update wherein the sender informs its cluster
    /// peers that it has run the match computation on a given pair of
    /// orders
    ///
    /// The peers should cache this order pair as completed, and not initiate
    /// handshakes with other peers on this order
    CacheSync(OrderIdentifier, OrderIdentifier),
}
