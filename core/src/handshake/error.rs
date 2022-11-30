//! Groups error types originating from the handshake manager

use std::fmt::Display;

/// The core error type for the handshake manager
#[derive(Clone, Debug)]
pub enum HandshakeManagerError {
    /// Error while setting up the handshake manager
    SetupError(String),
    /// Error resulting from a cancellation signal
    Cancelled(String),
}

impl Display for HandshakeManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
