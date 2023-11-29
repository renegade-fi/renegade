//! Jobs consumed by the handshake manager

use ark_mpc::network::QuicTwoPartyNet;
use circuit_types::wallet::Nullifier;
use common::types::{gossip::WrappedPeerId, wallet::OrderIdentifier};
use constants::SystemCurveGroup;
use gossip_api::{gossip::AuthenticatedGossipResponse, handshake::HandshakeMessage};
use libp2p::request_response::ResponseChannel;
use uuid::Uuid;

/// Represents a job for the handshake manager's thread pool to execute
#[allow(clippy::large_enum_variant)]
pub enum HandshakeExecutionJob {
    /// Update the handshake cache with an entry from an order pair that a
    /// cluster peer has executed
    CacheEntry {
        /// The first of the orders matched
        order1: OrderIdentifier,
        /// The second of the orders matched
        order2: OrderIdentifier,
    },
    /// Run the internal matching engine on the given order
    ///
    /// That is, check it against all other locally managed orders for a match.
    /// This is the simplest match path as it does not require a handshake
    /// with a remote peer. Both orders matched are known in the clear to
    /// the local peer
    InternalMatchingEngine {
        /// The order to match
        order: OrderIdentifier,
    },
    /// Indicates that the network manager has setup an MPC net and the
    /// receiving thread may begin executing a match over this network
    MpcNetSetup {
        /// The ID of the handshake request that this connection has been
        /// allocated for
        request_id: Uuid,
        /// The ID of the local peer in the subsequent MPC computation
        party_id: u64,
        /// The net that was setup for the party
        net: QuicTwoPartyNet<SystemCurveGroup>,
    },
    /// Indicates that the local peer should halt any MPCs active on the given
    /// nullifier
    ///
    /// This job is constructed when a nullifier is seen on chain, indicating
    /// that it is no longer valid to match on. The local party should
    /// hangup immediately to avoid leaking the order after opening
    MpcShootdown {
        /// The public share nullifier value seen on-chain; any in-flight MPCs
        /// on this nullifier are to be terminated
        nullifier: Nullifier,
    },
    /// Indicates that a cluster replica has initiated a match on the given
    /// order pair. The local peer should not schedule this order pair for a
    /// match for some duration
    PeerMatchInProgress {
        /// The first of the orders in the pair
        order1: OrderIdentifier,
        /// The second of the orders in the pair
        order2: OrderIdentifier,
    },
    /// Process a handshake request
    ProcessHandshakeMessage {
        /// The request identifier that will be used to track and index
        /// handshake communications
        request_id: Uuid,
        /// The peer requesting to handshake
        peer_id: WrappedPeerId,
        /// The handshake request message contents
        message: HandshakeMessage,
        /// The channel on which to send the response
        ///
        /// If the channel is `None`, the response should be forwarded
        /// as a new gossip request to the network manager directly
        response_channel: Option<ResponseChannel<AuthenticatedGossipResponse>>,
    },
    /// A request to initiate a handshake with a scheduled peer
    PerformHandshake {
        /// The order to attempt a handshake on
        order: OrderIdentifier,
    },
}
