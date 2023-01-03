use std::error::Error;
use std::fmt::{self, Display};

#[derive(Clone, Debug)]
/// The core error type used by the ExchangeConnection. All thrown errors are handled by the
/// PriceReporter, either for restarts or panics upon too many consecutive errors.
pub enum ExchangeConnectionError {
    /// An initial websocket subscription to a remote server failed.
    HandshakeFailure,
    /// A websocket remote connection hungup.
    ConnectionHangup,
    /// Could not parse a remote server message.
    InvalidMessage,
}

impl Error for ExchangeConnectionError {}
impl Display for ExchangeConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let display_string = match self {
            ExchangeConnectionError::HandshakeFailure => "HandshakeFailure",
            ExchangeConnectionError::ConnectionHangup => "ConnectionHangup",
            ExchangeConnectionError::InvalidMessage => "InvalidMessage",
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
            PriceReporterManagerError::TooManyFailures(exchange_connection_error) => {
                format!("TooManyFailures({})", exchange_connection_error)
            }
            PriceReporterManagerError::ManagerSetup(err) => {
                format!("ManagerSetup({})", err)
            }
        };
        write!(f, "{}", display_string)
    }
}
