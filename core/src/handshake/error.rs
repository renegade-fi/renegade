//! Groups error types originating from the handshake manager

use std::fmt::Display;

/// The core error type for the handshake manager
#[derive(Clone, Debug)]
pub enum HandshakeManagerError {
    /// A handshake was abandoned for the reason given in the parameter
    Abandoned(String),
    /// An error while collaboratively proving a statement
    Multiprover(String),
    /// An invalid request ID was passed in a message; i.e. the request ID is not known
    /// to the local state machine
    InvalidRequest(String),
    /// Error in MPC networking
    MpcNetwork(String),
    /// Error verifying a proof
    VerificationError(String),
    /// Error sending a message to the network
    SendMessage(String),
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
