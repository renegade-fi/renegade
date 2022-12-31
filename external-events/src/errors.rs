use std::error::Error;
use std::fmt::{self, Display};

#[derive(Clone, Debug)]
pub enum ReporterError {
    /// An initial websocket subscription to a remote server failed.
    _HandshakeFailure,
    /// A websocket remote connection hungup.
    ConnectionHangup,
    /// Could not parse a remote server message.
    _InvalidMessage,
}

impl Error for ReporterError {}
impl Display for ReporterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let display_string = match self {
            ReporterError::_HandshakeFailure => {
                "An initial websocket subscription to a remote server failed."
            }
            ReporterError::ConnectionHangup => "A websocket remote connection hungup.",
            ReporterError::_InvalidMessage => "Could not parse a remote server message.",
        };
        write!(f, "{}", display_string)
    }
}
