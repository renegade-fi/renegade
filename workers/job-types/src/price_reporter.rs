//! Defines all possible jobs for the PriceReporter.
use common::types::{
    exchange::{Exchange, ExchangeConnectionState, PriceReporterState},
    token::Token,
};
use std::collections::HashMap;
use tokio::sync::mpsc::{
    unbounded_channel, UnboundedReceiver as TokioUnboundedReceiver,
    UnboundedSender as TokioUnboundedSender,
};
use tokio::sync::oneshot::Sender as TokioSender;

/// The queue type for the price reporter
pub type PriceReporterQueue = TokioUnboundedSender<PriceReporterJob>;
/// The queue receiver type for the price reporter
pub type PriceReporterReceiver = TokioUnboundedReceiver<PriceReporterJob>;

/// Create a new price reporter queue and receiver
pub fn new_price_reporter_queue() -> (PriceReporterQueue, PriceReporterReceiver) {
    unbounded_channel()
}

/// All possible jobs that the PriceReporter accepts.
#[derive(Debug)]
pub enum PriceReporterJob {
    /// Create and start a new PriceReporter for a given token pair.
    ///
    /// If the PriceReporter does not yet exist, spawn it and begin publication
    /// to the global system bus. If the PriceReporter already exists and id
    /// is None, this is a no-op.
    ///
    /// If the PriceReporter already exists and id is Some, register this ID as
    /// a listener. This prevents tear-down of the PriceReporter, even if
    /// subscribers on the system bus stop listening. Cleanup is done via
    /// DropListenerID, and callees are responsible for dropping all
    /// listener IDs.
    StartPriceReporter {
        /// The base Token
        base_token: Token,
        /// The quote Token
        quote_token: Token,
    },
    /// Peek at the median price report
    PeekMedian {
        /// The base Token
        base_token: Token,
        /// The quote Token
        quote_token: Token,
        /// The return channel for the price report
        channel: TokioSender<PriceReporterState>,
    },
    /// Peek at each ExchangeConnectionState
    PeekAllExchanges {
        /// The base Token
        base_token: Token,
        /// The quote Token
        quote_token: Token,
        /// The return channel for the ExchangeConnectionStates
        channel: TokioSender<HashMap<Exchange, ExchangeConnectionState>>,
    },
}
