//! Groups error types originating from the handshake manager

use state::error::StateError;

/// The core error type for the handshake manager
#[derive(Clone, Debug, thiserror::Error)]
pub enum HandshakeManagerError {
    /// Error resulting from a cancellation signal
    #[error("handshake manager worker cancelled: {0}")]
    Cancelled(String),
    /// An invalid request ID was passed in a message; i.e. the request ID is
    /// not known to the local state machine
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// Error in MPC networking
    #[error("mpc network error: {0}")]
    MpcNetwork(String),
    /// An MpcShootdown request has stopped the handshake
    #[error("mpc shootdown")]
    MpcShootdown,
    /// An error while collaboratively proving a statement
    #[error("multiprover execution error: {0}")]
    Multiprover(String),
    /// Necessary price data was not available for a token pair
    #[error("no price data: {0}")]
    NoPriceData(String),
    /// Error interacting with the price reporter
    #[error("price reporter error: {0}")]
    PriceReporter(String),
    /// Error sending a message to the network
    #[error("error sending message: {0}")]
    SendMessage(String),
    /// Error while setting up the handshake manager
    #[error("error setting up handshake manager: {0}")]
    SetupError(String),
    /// An error executing a settlement task
    #[error("error running task: {0}")]
    TaskError(String),
    /// Error interacting with global state
    #[error("state error: {0}")]
    State(String),
    /// Error verifying a proof
    #[error("proof verification error: {0}")]
    VerificationError(String),
}

impl HandshakeManagerError {
    /// Create a new error from an invalid request
    #[allow(clippy::needless_pass_by_value)]
    pub fn invalid_request<T: ToString>(e: T) -> Self {
        HandshakeManagerError::InvalidRequest(e.to_string())
    }

    /// Create a new error from a price reporter error
    #[allow(clippy::needless_pass_by_value)]
    pub fn price_reporter<T: ToString>(e: T) -> Self {
        HandshakeManagerError::PriceReporter(e.to_string())
    }

    /// Create a new error from a state error
    #[allow(clippy::needless_pass_by_value)]
    pub fn state<T: ToString>(e: T) -> Self {
        HandshakeManagerError::State(e.to_string())
    }
}

impl From<StateError> for HandshakeManagerError {
    fn from(value: StateError) -> Self {
        HandshakeManagerError::State(value.to_string())
    }
}
