//! Defines jobs that other workers in the relayer may enqueue for the handshake module

use libp2p::request_response::ResponseChannel;
use mpc_ristretto::network::QuicTwoPartyNet;

use crate::{
    api::{gossip::GossipResponse, handshake::HandshakeMessage},
    gossip::types::WrappedPeerId,
};

use super::manager::OrderIdentifier;

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
    /// Indicates that the network manager has setup an MPC net and the receiving thread
    /// may begin executing a match over this network
    MpcNetSetup {
        /// The ID of the local peer in the subsequent MPC computation
        party_id: u64,
        /// The net that was setup for the party
        net: QuicTwoPartyNet,
    },
    /// Update the handshake cache with an entry from an order pair that a cluster
    /// peer has executed
    CacheEntry {
        /// The first of the orders matched
        order1: OrderIdentifier,
        /// The second of the orderes matched
        order2: OrderIdentifier,
    },
}
