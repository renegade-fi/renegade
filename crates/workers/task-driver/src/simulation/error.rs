//! Error type for the task simulator

use serde::{Deserialize, Serialize};
use types_account::AccountError;

/// The error type emitted during task simulation
#[derive(Clone, Debug, Serialize, Deserialize, thiserror::Error)]
pub enum TaskSimulationError {
    /// An account error occurred
    #[error("account error: {0}")]
    Account(#[from] AccountError),
    /// An invalid task was provided to the simulator
    #[error("invalid task: {0}")]
    InvalidTask(&'static str),
    /// Invalid wallet state to apply a transition
    #[error("invalid wallet state: {0}")]
    InvalidWalletState(&'static str),
    /// Invalid task state on a task provided to the simulator
    #[error("invalid task state: {0}")]
    InvalidTaskState(String),
}

impl TaskSimulationError {
    /// Create a new task simulation error
    #[allow(clippy::needless_pass_by_value)]
    pub fn invalid_task_state<T: ToString>(message: T) -> Self {
        Self::InvalidTaskState(message.to_string())
    }
}
