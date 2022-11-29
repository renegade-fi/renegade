use libp2p::request_response::ResponseChannel;

use crate::api::{gossip::GossipResponse, hearbeat::HeartbeatMessage};

use super::types::WrappedPeerId;

/// Defines a heartbeat job that can be enqueued by other workers in a relayer
pub enum HeartbeatExecutorJob {
    ExecuteHeartbeats,
    HandleHeartbeatReq {
        peer_id: WrappedPeerId,
        message: HeartbeatMessage,
        channel: ResponseChannel<GossipResponse>,
    },
    HandleHeartbeatResp {
        peer_id: WrappedPeerId,
        message: HeartbeatMessage,
    },
}
