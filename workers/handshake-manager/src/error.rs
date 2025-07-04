//! Groups error types originating from the handshake manager

use std::fmt::Display;

use state::error::StateError;

/// The core error type for the handshake manager
#[derive(Clone, Debug)]
pub enum HandshakeManagerError {
    /// Error resulting from a cancellation signal
    Cancelled(String),
    /// An invalid request ID was passed in a message; i.e. the request ID is
    /// not known to the local state machine
    InvalidRequest(String),
    /// Error in MPC networking
    MpcNetwork(String),
    /// An MpcShootdown request has stopped the handshake
    MpcShootdown,
    /// An error while collaboratively proving a statement
    Multiprover(String),
    /// Necessary price data was not available for a token pair
    NoPriceData(String),
    /// Error interacting with the price reporter
    PriceReporter(String),
    /// Error sending a message to the network
    SendMessage(String),
    /// Error while setting up the handshake manager
    SetupError(String),
    /// An error executing a settlement task
    TaskError(String),
    /// Error interacting with global state
    State(String),
    /// Error verifying a proof
    VerificationError(String),
}

impl HandshakeManagerError {
    /// Create a new error from a state error
    #[allow(clippy::needless_pass_by_value)]
    pub fn state<T: ToString>(e: T) -> Self {
        HandshakeManagerError::State(e.to_string())
    }

    /// Create a new error from an invalid request
    #[allow(clippy::needless_pass_by_value)]
    pub fn invalid_request<T: ToString>(e: T) -> Self {
        HandshakeManagerError::InvalidRequest(e.to_string())
    }
}

impl Display for HandshakeManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<StateError> for HandshakeManagerError {
    fn from(value: StateError) -> Self {
        HandshakeManagerError::State(value.to_string())
    }
}
