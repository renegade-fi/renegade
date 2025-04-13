//! Groups top-level errors useful throughout the relayer

use std::error::Error;
use std::fmt::Display;

use state::error::StateError;
use system_clock::SystemClockError;

/// An error type at the coordinator level
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum CoordinatorError {
    /// An error setting up the connection to the Arbitrum RPC node
    Arbitrum(String),
    /// Error attempting to recover a failed worker
    Recovery(String),
    /// Failure to send a cancel signal to a worker
    CancelSend(String),
    /// An error setting up the relayer
    Setup(String),
    /// An error setting up global state
    State(String),
    /// An error setting up the system clock timers
    Clock(String),
}

impl CoordinatorError {
    /// New setup error
    #[allow(clippy::needless_pass_by_value)]
    pub fn setup<T: ToString>(msg: T) -> Self {
        CoordinatorError::Setup(msg.to_string())
    }
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

impl From<SystemClockError> for CoordinatorError {
    fn from(value: SystemClockError) -> Self {
        CoordinatorError::Clock(value.0)
    }
}
