//! Error types for the task driver

use std::error::Error;
use std::fmt::Display;

use state::error::StateError;

use crate::traits::TaskError;

/// The error type emitted by the task driver
#[derive(Clone, Debug)]
pub enum TaskDriverError {
    /// A task failed to execute
    TaskFailed,
    /// The job channel for the task driver is closed
    JobQueueClosed,
    /// A task was preempted while running
    Preempted,
    /// An error querying global state
    State(String),
    /// An error running a task
    TaskError(String),
}

impl Display for TaskDriverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for TaskDriverError {}

impl From<StateError> for TaskDriverError {
    fn from(e: StateError) -> Self {
        TaskDriverError::State(e.to_string())
    }
}

impl<E: TaskError> From<E> for TaskDriverError {
    fn from(value: E) -> Self {
        TaskDriverError::TaskError(value.to_string())
    }
}
