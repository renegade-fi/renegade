//! Groups job definitions for the gossip server
//! These jobs are enqueued for execution by other workers within the relayer

use libp2p::request_response::ResponseChannel;

use crate::api::{
    cluster_management::{ClusterJoinMessage, ReplicateMessage},
    gossip::GossipResponse,
    hearbeat::HeartbeatMessage,
};

use super::types::WrappedPeerId;

/// Defines a heartbeat job that can be enqueued by other workers in a relayer
#[derive(Debug)]
pub enum GossipServerJob {
    /// Job type for the heartbeat executor to send an outbound heartbeat request
    ExecuteHeartbeat(WrappedPeerId),
    /// Handle an incoming cluster management job
    Cluster(ClusterManagementJob),
    /// Handle an incoming heartbeat request from a peer
    HandleHeartbeatReq {
        /// The peer sending the request
        peer_id: WrappedPeerId,
        /// The message contents
        message: HeartbeatMessage,
        /// A channel on which to send the response
        channel: ResponseChannel<GossipResponse>,
    },
    /// Handle an incoming heartbeat response from a peer
    HandleHeartbeatResp {
        /// The peer sending a heartbeat response
        peer_id: WrappedPeerId,
        /// The message contents
        message: HeartbeatMessage,
    },
}

/// Defines a job schedule for a cluster management task
#[derive(Clone, Debug)]
pub enum ClusterManagementJob {
    /// A request from a peer to join the local peer's cluster
    ClusterJoinRequest(ClusterJoinMessage),
    /// Replicate a set of wallets forwarded from a peer
    ReplicateRequest(ReplicateMessage),
}
