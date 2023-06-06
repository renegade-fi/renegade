//! Defines all possible jobs for the PriceReporterManager.
use std::collections::HashMap;
use tokio::sync::oneshot::Sender as TokioSender;

use super::{
    exchanges::{Exchange, ExchangeConnectionState},
    reporter::PriceReporterState,
    tokens::Token,
};

/// All possible jobs that the PriceReporterManager accepts.
#[derive(Debug)]
pub enum PriceReporterManagerJob {
    /// Create and start a new PriceReporter for a given token pair.
    ///
    /// If the PriceReporter does not yet exist, spawn it and begin publication to the global
    /// system bus. If the PriceReporter already exists and id is None, this is a no-op.
    ///
    /// If the PriceReporter already exists and id is Some, register this ID as a listener. This
    /// prevents tear-down of the PriceReporter, even if subscribers on the system bus stop
    /// listening. Cleanup is done via DropListenerID, and callees are responsible for
    /// dropping all listener IDs.
    StartPriceReporter {
        /// The base Token
        base_token: Token,
        /// The quote Token
        quote_token: Token,
        /// The channel to send a response after completion
        channel: TokioSender<()>,
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
