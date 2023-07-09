//! Groups error types originating from the handshake manager

use std::fmt::Display;

/// The core error type for the handshake manager
#[derive(Clone, Debug)]
pub enum HandshakeManagerError {
    /// Error resulting from a cancellation signal
    Cancelled(String),
    /// An invalid request ID was passed in a message; i.e. the request ID is not known
    /// to the local state machine
    InvalidRequest(String),
    /// Error in MPC networking
    MpcNetwork(String),
    /// An MpcShootdown request has stopped the handshake
    MpcShootdown,
    /// An error while collaboratively proving a statement
    Multiprover(String),
    /// Necessary price data was not available for a token pair
    NoPriceData(String),
    /// Error sending a message to the network
    SendMessage(String),
    /// Error while setting up the handshake manager
    SetupError(String),
    /// An error executing a settlement task
    TaskError(String),
    /// A state element was referenced, but cannot be found locally
    ///
    /// This may happen if, for example, an order is cancelled during the course
    /// of a match
    StateNotFound(String),
    /// Error verifying a proof
    VerificationError(String),
}

impl Display for HandshakeManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
