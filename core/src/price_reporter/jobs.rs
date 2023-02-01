//! Defines all possible jobs for the PriceReporterManager.
use crossbeam::channel::Sender;
use ring_channel::RingReceiver;
use std::collections::{HashMap, HashSet};

use super::{
    exchanges::{Exchange, ExchangeConnectionState},
    manager::PriceReporterListenerID,
    reporter::{PriceReport, PriceReporterState},
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
    /// listening. Cleanup is done via DropListenereID, and callees are responsible for
    /// dropping all listener IDs.
    StartPriceReporter {
        /// The base Token
        base_token: Token,
        /// The quote Token
        quote_token: Token,
        /// The ID of the listener
        id: Option<PriceReporterListenerID>,
        /// The channel to send a response after completion
        channel: Sender<()>,
    },
    /// Drop the specified id from the listeners
    DropListenerID {
        /// The base Token
        base_token: Token,
        /// The quote Token
        quote_token: Token,
        /// The ID of the listener to drop
        id: PriceReporterListenerID,
        /// The channel to send a response after completion
        channel: Sender<()>,
    },
    /// Peek at the median price report
    PeekMedian {
        /// The base Token
        base_token: Token,
        /// The quote Token
        quote_token: Token,
        /// The return channel for the price report
        channel: Sender<PriceReporterState>,
    },
    /// Peek at each ExchangeConnectionState
    PeekAllExchanges {
        /// The base Token
        base_token: Token,
        /// The quote Token
        quote_token: Token,
        /// The return channel for the ExchangeConnectionStates
        channel: Sender<HashMap<Exchange, ExchangeConnectionState>>,
    },
    /// Create a forked median receiver
    CreateNewMedianReceiver {
        /// The base Token
        base_token: Token,
        /// The quote Token
        quote_token: Token,
        /// The return channel for the new receiver
        channel: Sender<RingReceiver<PriceReport>>,
    },
    /// Get all the exchanges that this price reporter supports
    GetSupportedExchanges {
        /// The base Token
        base_token: Token,
        /// The quote Token
        quote_token: Token,
        /// The return channel for the supported exchanges
        channel: Sender<HashSet<Exchange>>,
    },
    /// Get all the supported exchanges that are in a healthy state
    GetHealthyExchanges {
        /// The base Token
        base_token: Token,
        /// The quote Token
        quote_token: Token,
        /// The return channel for the healthy exchanges
        channel: Sender<HashSet<Exchange>>,
    },
}
