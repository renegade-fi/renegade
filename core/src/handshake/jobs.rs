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
    ProcessHandshakeMessage {
        /// The peer requesting to handshake
        peer_id: WrappedPeerId,
        /// The handshake request message contents
        message: HandshakeMessage,
        /// The channel on which to send the response
        ///
        /// If the channel is `None`, the response should be forwarded
        /// as a new gossip request to the network manager directly
        response_channel: Option<ResponseChannel<GossipResponse>>,
    },
}
