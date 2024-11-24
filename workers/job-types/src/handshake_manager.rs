//! Jobs consumed by the handshake manager

use ark_mpc::network::QuicTwoPartyNet;
use circuit_types::wallet::Nullifier;
use common::types::{
    gossip::WrappedPeerId,
    wallet::{Order, OrderIdentifier},
};
use constants::SystemCurveGroup;
use external_api::bus_message::gen_atomic_match_response_topic;
use gossip_api::request_response::{handshake::HandshakeMessage, AuthenticatedGossipResponse};
use libp2p::request_response::ResponseChannel;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender as TokioSender};
use util::metered_channels::MeteredTokioReceiver;
use uuid::Uuid;

/// The name of the handshake manager queue, used to label queue length metrics
const HANDSHAKE_MANAGER_QUEUE_NAME: &str = "handshake_manager";

/// The response type for external matching jobs
///
/// TODO: Define this type
pub type ExternalMatchingResponse = ();

/// The job queue for the handshake manager
pub type HandshakeManagerQueue = TokioSender<HandshakeManagerJob>;
/// The job queue receiver for the handshake manager
pub type HandshakeManagerReceiver = MeteredTokioReceiver<HandshakeManagerJob>;

/// Create a new handshake manager queue and receiver
pub fn new_handshake_manager_queue() -> (HandshakeManagerQueue, HandshakeManagerReceiver) {
    let (send, recv) = unbounded_channel();
    (send, MeteredTokioReceiver::new(recv, HANDSHAKE_MANAGER_QUEUE_NAME))
}

/// Represents a job for the handshake manager's thread pool to execute
#[allow(clippy::large_enum_variant)]
pub enum HandshakeManagerJob {
    // --- Handshakes and Matching --- //
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
    /// Run the external matching engine on the given order
    ExternalMatchingEngine {
        /// The external order to match
        order: Order,
        /// The system bus topic on which to send the resulting external match
        ///
        /// We send on the bus rather than directly through a oneshot for two
        /// reasons:
        /// 1. Sending via a oneshot would require storing the oneshot in state
        ///    to use in the task driver, which is not possible
        /// 2. Sending via the bus avoids needing to clone a oneshot to retry
        response_topic: String,
        /// Whether or not to only generate a quote, without proving validity
        /// for the order's match
        only_quote: bool,
    },
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
        response_channel: Option<ResponseChannel<AuthenticatedGossipResponse>>,
    },
    /// A request to initiate a handshake with a scheduled peer
    PerformHandshake {
        /// The order to attempt a handshake on
        order: OrderIdentifier,
    },

    // --- Caching --- //
    /// Update the handshake cache with an entry from an order pair that a
    /// cluster peer has executed
    CacheEntry {
        /// The first of the orders matched
        order1: OrderIdentifier,
        /// The second of the orders matched
        order2: OrderIdentifier,
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

    // --- Networking --- //
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
}

impl HandshakeManagerJob {
    /// Get a quote for an external order
    pub fn get_external_quote(order: Order) -> (Self, String) {
        Self::new_external_match_job(order, true /* quote_only */)
    }

    /// Run the external matching engine and create a bundle
    pub fn get_external_match_bundle(order: Order) -> (Self, String) {
        Self::new_external_match_job(order, false /* quote_only */)
    }

    /// Create a new external matching job
    pub fn new_external_match_job(order: Order, quote_only: bool) -> (Self, String) {
        let topic = gen_atomic_match_response_topic();
        (
            Self::ExternalMatchingEngine {
                order,
                response_topic: topic.clone(),
                only_quote: quote_only,
            },
            topic,
        )
    }
}
