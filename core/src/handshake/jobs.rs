use libp2p::request_response::ResponseChannel;

use crate::{
    api::{gossip::GossipResponse, handshake::HandshakeMessage},
    gossip::types::WrappedPeerId,
};

/**
 * This file groups type definitions for the handshake module
 */

// Represents a job for the handshake manager's thread pool to execute
pub enum HandshakeExecutionJob {
    ProcessHandshakeRequest {
        peer_id: WrappedPeerId,
        message: HandshakeMessage,
        response_channel: ResponseChannel<GossipResponse>,
    },
}
