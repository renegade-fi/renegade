//! Groups error types originating from the matching engine worker

use state::error::StateError;

/// The core error type for the matching engine worker
#[derive(Clone, Debug, thiserror::Error)]
pub enum MatchingEngineError {
    /// Error resulting from a cancellation signal
    #[error("matching engine worker cancelled: {0}")]
    Cancelled(String),
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

impl MatchingEngineError {
    /// Create a new error from a no price data error
    #[allow(clippy::needless_pass_by_value)]
    pub fn no_price<T: ToString>(e: T) -> Self {
        MatchingEngineError::NoPriceData(e.to_string())
    }

    /// Create a new error from a price reporter error
    #[allow(clippy::needless_pass_by_value)]
    pub fn price_reporter<T: ToString>(e: T) -> Self {
        MatchingEngineError::PriceReporter(e.to_string())
    }

    /// Create a new error from a send message error
    #[allow(clippy::needless_pass_by_value)]
    pub fn send_message<T: ToString>(e: T) -> Self {
        MatchingEngineError::SendMessage(e.to_string())
    }

    /// Create a new error from a setup error
    #[allow(clippy::needless_pass_by_value)]
    pub fn setup<T: ToString>(e: T) -> Self {
        MatchingEngineError::SetupError(e.to_string())
    }

    /// Create a new error from a state error
    #[allow(clippy::needless_pass_by_value)]
    pub fn state<T: ToString>(e: T) -> Self {
        MatchingEngineError::State(e.to_string())
    }

    /// Create a new error from a task error
    #[allow(clippy::needless_pass_by_value)]
    pub fn task<T: ToString>(e: T) -> Self {
        MatchingEngineError::TaskError(e.to_string())
    }
}

impl From<StateError> for MatchingEngineError {
    fn from(value: StateError) -> Self {
        MatchingEngineError::State(value.to_string())
    }
}
