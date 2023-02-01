//! Defines all Error types, both for individual ExchangeConnections and the PriceReporter itself.
use std::error::Error;
use std::fmt::{self, Display};

#[derive(Clone, Debug)]
/// The core error type used by the ExchangeConnection. All thrown errors are handled by the
/// PriceReporter, either for restarts or panics upon too many consecutive errors.
pub enum ExchangeConnectionError {
    /// An initial websocket subscription to a remote server failed.
    HandshakeFailure(String),
    /// A websocket remote connection hungup.
    ConnectionHangup(String),
    /// Could not parse a remote server message.
    InvalidMessage(String),
}

impl Error for ExchangeConnectionError {}
impl Display for ExchangeConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let display_string = match self {
            ExchangeConnectionError::HandshakeFailure(err) => format!("HandshakeFailure({})", err),
            ExchangeConnectionError::ConnectionHangup(err) => format!("ConnectionHangup({})", err),
            ExchangeConnectionError::InvalidMessage(err) => format!("InvalidMessage({})", err),
        };
        write!(f, "{}", display_string)
    }
}

#[derive(Clone, Debug)]
/// The core error type thrown by the PriceReporterManager worker.
pub enum PriceReporterManagerError {
    /// An external cancel was requested by the worker manager
    Cancelled(String),
    /// The spawning of the initial PriceReporterManager execution thread failed
    ManagerSetup(String),
    /// Tried to register a listener ID that is already registered
    AlreadyListening(String),
    /// Tried to drop a listener ID that was not listening
    ListenerNotFound(String),
    /// Tried to query information from a PriceReporter that does not exist. Callers should send a
    /// StartPriceReporter job first
    PriceReporterNotCreated(String),
    /// In one of the PriceReporters, one of the ExchangeConnections failed too many times in a
    /// row.
    TooManyFailures(ExchangeConnectionError),
}

impl Error for PriceReporterManagerError {}
impl Display for PriceReporterManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let display_string = match self {
            PriceReporterManagerError::Cancelled(err) => {
                format!("Cancelled({})", err)
            }
            PriceReporterManagerError::ManagerSetup(err) => {
                format!("ManagerSetup({})", err)
            }
            PriceReporterManagerError::AlreadyListening(err) => {
                format!("AlreadyListening({})", err)
            }
            PriceReporterManagerError::ListenerNotFound(err) => {
                format!("ListenerNotFound({})", err)
            }
            PriceReporterManagerError::PriceReporterNotCreated(err) => {
                format!("PriceReporterNotCreated({})", err)
            }
            PriceReporterManagerError::TooManyFailures(exchange_connection_error) => {
                format!("TooManyFailures({})", exchange_connection_error)
            }
        };
        write!(f, "{}", display_string)
    }
}
