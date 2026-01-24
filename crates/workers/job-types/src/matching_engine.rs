//! Jobs consumed by the matching engine worker

use circuit_types::{Amount, fixed_point::FixedPoint};
use constants::GLOBAL_MATCHING_POOL;
use system_bus::gen_atomic_match_response_topic;
use types_account::{MatchingPoolName, OrderId, order::Order};
use types_core::TimestampedPrice;
use util::channels::{TracedTokioReceiver, TracedTokioSender, new_traced_tokio_channel};

/// The job queue for the matching engine worker
pub type MatchingEngineWorkerQueue = TracedTokioSender<MatchingEngineWorkerJob>;
/// The job queue receiver for the matching engine worker
pub type MatchingEngineWorkerReceiver = TracedTokioReceiver<MatchingEngineWorkerJob>;

/// Create a new matching engine worker queue and receiver
pub fn new_matching_engine_worker_queue()
-> (MatchingEngineWorkerQueue, MatchingEngineWorkerReceiver) {
    new_traced_tokio_channel()
}

/// Represents a job for the matching engine worker's thread pool to execute
#[allow(clippy::large_enum_variant)]
pub enum MatchingEngineWorkerJob {
    // --- Handshakes and Matching --- //
    /// Run the internal matching engine on the given order
    ///
    /// That is, check it against all other locally managed orders for a match.
    /// This is the simplest match path as it does not require a handshake
    /// with a remote peer. Both orders matched are known in the clear to
    /// the local peer
    InternalMatchingEngine {
        /// The order to match
        order: OrderId,
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
}

impl MatchingEngineWorkerJob {
    /// Run the internal matching engine on a given order
    pub fn run_internal_engine(order: OrderId) -> Self {
        Self::InternalMatchingEngine { order }
    }

    /// Get a quote for an external order
    pub fn get_external_quote(order: Order) -> (Self, String) {
        let opt = ExternalMatchingEngineOptions::only_quote();
        Self::new_external_match_job(order, opt)
    }

    /// Get an external match bundle with a previously committed-to price
    pub fn get_external_match_bundle_with_price(
        order: Order,
        price: TimestampedPrice,
    ) -> (Self, String) {
        let opt = ExternalMatchingEngineOptions::new().with_price(price);
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
    /// The fee take rate for the relayer in the match
    ///
    /// This only applies to the external party
    pub relayer_fee_rate: FixedPoint,
    /// The price to use for the external match. If `None`, the price will
    /// be sampled by the engine
    ///
    /// This is used to fulfill a previously committed-to quote at the
    /// api-layer
    pub price: Option<TimestampedPrice>,
    /// The minimum input amount to use for a full fill
    pub min_input_amount: Option<Amount>,
    /// The matching pool to request a quote from
    ///
    /// If specified, the matching engine will only consider crossing orders in
    /// the given pool. If unspecified, all orders are considered candidates for
    /// a match
    pub matching_pool: Option<MatchingPoolName>,
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

    /// Set the relayer fee rate
    pub fn with_relayer_fee_rate(mut self, rate: FixedPoint) -> Self {
        self.relayer_fee_rate = rate;
        self
    }

    /// Set the price
    pub fn with_price(mut self, price: TimestampedPrice) -> Self {
        self.price = Some(price);
        self
    }

    /// Set the min input amount
    pub fn with_min_input_amount(mut self, amount: Amount) -> Self {
        self.min_input_amount = Some(amount);
        self
    }

    /// Set the matching pool
    pub fn with_matching_pool(mut self, pool: Option<MatchingPoolName>) -> Self {
        self.matching_pool = pool;
        self
    }

    /// Get the matching pool
    pub fn matching_pool(&self) -> MatchingPoolName {
        self.matching_pool.clone().unwrap_or(GLOBAL_MATCHING_POOL.to_string())
    }
}
