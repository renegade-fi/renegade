//! Jobs consumed by the handshake manager

use std::time::Duration;

use ark_mpc::network::QuicTwoPartyNet;
use circuit_types::{wallet::Nullifier, Amount};
use common::types::{
    gossip::WrappedPeerId,
    price::TimestampedPrice,
    wallet::{Order, OrderIdentifier},
};
use constants::SystemCurveGroup;
use external_api::bus_message::gen_atomic_match_response_topic;
use gossip_api::request_response::{handshake::HandshakeMessage, AuthenticatedGossipResponse};
use libp2p::request_response::ResponseChannel;
use util::channels::{new_traced_tokio_channel, TracedTokioReceiver, TracedTokioSender};
use uuid::Uuid;

/// The job queue for the handshake manager
pub type HandshakeManagerQueue = TracedTokioSender<HandshakeManagerJob>;
/// The job queue receiver for the handshake manager
pub type HandshakeManagerReceiver = TracedTokioReceiver<HandshakeManagerJob>;

/// Create a new handshake manager queue and receiver
pub fn new_handshake_manager_queue() -> (HandshakeManagerQueue, HandshakeManagerReceiver) {
    new_traced_tokio_channel()
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
        /// The options for the external matching engine
        options: ExternalMatchingEngineOptions,
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
        let opt = ExternalMatchingEngineOptions::only_quote();
        Self::new_external_match_job(order, opt)
    }

    /// Get an external match bundle with a previously committed-to price
    pub fn get_external_match_bundle_with_price(
        order: Order,
        price: TimestampedPrice,
        bundle_duration: Duration,
    ) -> (Self, String) {
        let opt = ExternalMatchingEngineOptions::new()
            .with_bundle_duration(bundle_duration)
            .with_price(price);
        Self::new_external_match_job(order, opt)
    }

    /// Run the external matching engine and create a bundle
    pub fn get_external_match_bundle(order: Order) -> (Self, String) {
        let opt = ExternalMatchingEngineOptions::default();
        Self::new_external_match_job(order, opt)
    }

    /// Create a new external matching job
    pub fn new_external_match_job(
        order: Order,
        options: ExternalMatchingEngineOptions,
    ) -> (Self, String) {
        let topic = gen_atomic_match_response_topic();
        (Self::ExternalMatchingEngine { order, response_topic: topic.clone(), options }, topic)
    }
}

/// Represents options passed to the external matching engine
#[derive(Clone, Default)]
pub struct ExternalMatchingEngineOptions {
    /// Whether or not to only generate a quote, without proving validity
    /// for the order's match
    pub only_quote: bool,
    /// Whether or not to allow shared access to the resulting bundle
    ///
    /// If true, the bundle may be sent to other clients requesting an external
    /// match. If false, the bundle will be exclusively held for
    /// `bundle_duration`
    pub allow_shared: bool,
    /// Whether or not to emit a bounded match rather than an exact match
    ///
    /// A `BoundedMatchResult` is one in which the exact `base_amount` is not
    /// known at the time the proof is generated. Rather, the submitting
    /// party will choose a `base_amount` in between the supplied bounds.
    ///
    /// The matching engine, then, must find a match but emit a match result
    /// that has appropriate (and valid) bounds on the `base_amount`.
    pub bounded_match: bool,
    /// The duration for which a match bundle is valid; i.e. for which the task
    /// driver should lock the matched wallet's queue
    pub bundle_duration: Duration,
    /// The price to use for the external match. If `None`, the price will
    /// be sampled by the engine
    ///
    /// This is used to fulfill a previously committed-to quote at the
    /// api-layer
    pub price: Option<TimestampedPrice>,
    /// The exact quote amount to use for a full fill
    pub exact_quote_amount: Option<Amount>,
    /// The minimum quote amount to use for a full fill
    pub min_quote_amount: Option<Amount>,
}

impl ExternalMatchingEngineOptions {
    /// Create a new, default external matching engine options
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new external matching engine options with only a quote
    pub fn only_quote() -> Self {
        Self::new().with_only_quote(true)
    }

    /// Set whether to only generate a quote
    pub fn with_only_quote(mut self, only_quote: bool) -> Self {
        self.only_quote = only_quote;
        self
    }

    /// Set whether to allow shared access to the resulting bundle
    pub fn with_allow_shared(mut self, allow_shared: bool) -> Self {
        self.allow_shared = allow_shared;
        self
    }

    /// Set whether to emit a bounded match
    pub fn with_bounded_match(mut self, bounded_match: bool) -> Self {
        self.bounded_match = bounded_match;
        self
    }

    /// Set the bundle duration
    pub fn with_bundle_duration(mut self, duration: Duration) -> Self {
        self.bundle_duration = duration;
        self
    }

    /// Set the price
    pub fn with_price(mut self, price: TimestampedPrice) -> Self {
        self.price = Some(price);
        self
    }

    /// Set the exact quote amount
    pub fn with_exact_quote_amount(mut self, amount: Amount) -> Self {
        self.exact_quote_amount = Some(amount);
        self
    }

    /// Set the min quote amount
    pub fn with_min_quote_amount(mut self, amount: Amount) -> Self {
        self.min_quote_amount = Some(amount);
        self
    }
}
