//! Error type for the task simulator

use std::error::Error;
use std::fmt::Display;

use serde::{Deserialize, Serialize};

/// The error type emitted during task simulation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TaskSimulationError {
    /// An invalid task was provided to the simulator
    InvalidTask(&'static str),
    /// Invalid wallet state to apply a transition
    InvalidWalletState(&'static str),
    /// Invalid task state on a task provided to the simulator
    InvalidTaskState(String),
}

impl Display for TaskSimulationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for TaskSimulationError {}

impl TaskSimulationError {
    /// Create a new task simulation error
    #[allow(clippy::needless_pass_by_value)]
    pub fn invalid_task_state<T: ToString>(message: T) -> Self {
        Self::InvalidTaskState(message.to_string())
    }
}
