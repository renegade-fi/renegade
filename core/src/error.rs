//! Groups top-level errors useful throughout the relayer

use std::error::Error;
use std::fmt::Display;

use statev2::error::StateError;

/// An error type at the coordinator level
#[derive(Clone, Debug)]
pub enum CoordinatorError {
    /// An error setting up the connection to the Arbitrum RPC node
    Arbitrum(String),
    /// Error attempting to recover a failed worker
    Recovery(String),
    /// Failure to send a cancel signal to a worker
    CancelSend(String),
    /// An error setting up global state
    State(String),
}

impl Error for CoordinatorError {}
impl Display for CoordinatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<StateError> for CoordinatorError {
    fn from(value: StateError) -> Self {
        CoordinatorError::State(value.to_string())
    }
}
