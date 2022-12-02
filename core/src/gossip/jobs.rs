//! Groups job definitions for the gossip server
//! These jobs are enqueued for execution by other workers within the relayer

use libp2p::request_response::ResponseChannel;

use crate::api::{gossip::GossipResponse, hearbeat::HeartbeatMessage};

use super::types::WrappedPeerId;

/// Defines a heartbeat job that can be enqueued by other workers in a relayer
#[derive(Debug)]
pub enum HeartbeatExecutorJob {
    /// Job type for the heartbeat executor to send outbound heartbeat requests to peers
    ExecuteHeartbeats,
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
