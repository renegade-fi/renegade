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
