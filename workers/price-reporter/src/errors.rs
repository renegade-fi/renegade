//! Defines all Error types, both for individual ExchangeConnections and the
//! PriceReporter itself.
use std::error::Error;
use std::fmt::{self, Display};

use common::types::exchange::Exchange;

/// The core error type used by the ExchangeConnection. All thrown errors are
/// handled by the PriceReporter, either for restarts or panics upon too many
/// consecutive errors.
#[derive(Clone, Debug)]
pub enum ExchangeConnectionError {
    /// A websocket remote connection hangup.
    ConnectionHangup(String),
    /// An initial websocket subscription to a remote server failed.
    HandshakeFailure(String),
    /// Could not parse a remote server message.
    InvalidMessage(String),
    /// The maximum retry count was exceeded while trying to re-establish
    /// an exchange connection
    MaxRetries(Exchange),
    /// Error sending on the `write` end of the websocket
    SendError(String),
}

impl Error for ExchangeConnectionError {}
impl Display for ExchangeConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// The core error type thrown by the PriceReporterManager worker.
#[derive(Clone, Debug)]
pub enum PriceReporterManagerError {
    /// An external cancel was requested by the worker manager
    Cancelled(String),
    /// The spawning of the initial PriceReporterManager execution thread failed
    ManagerSetup(String),
    /// Error creating a PriceReporter
    PriceReporterCreation(String),
    /// Tried to query information from a PriceReporter that does not exist.
    /// Callers should send a StartPriceReporter job first
    PriceReporterNotCreated(String),
    /// In one of the PriceReporters, one of the ExchangeConnections failed too
    /// many times in a row.
    _TooManyFailures(ExchangeConnectionError),
}

impl Error for PriceReporterManagerError {}
impl Display for PriceReporterManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
