//! Defines jobs that other workers in the relayer may enqueue for the handshake module

use libp2p::request_response::ResponseChannel;

use crate::{
    api::{gossip::GossipResponse, handshake::HandshakeMessage},
    gossip::types::WrappedPeerId,
};

/// Represents a job for the handshake manager's thread pool to execute
#[derive(Debug)]
pub enum HandshakeExecutionJob {
    /// Process a handshake request
    ProcessHandshakeRequest {
        /// The peer requesting to handshake
        peer_id: WrappedPeerId,
        /// The handshake request message contents
        message: HandshakeMessage,
        /// The channel on which to send the response
        response_channel: ResponseChannel<GossipResponse>,
    },
}
