//! Error types for the task driver

use state::error::StateError;

use crate::traits::TaskError;

/// The error type emitted by the task driver
#[derive(Clone, Debug, thiserror::Error)]
pub enum TaskDriverError {
    /// A task failed to execute
    #[error("task failed to execute")]
    TaskFailed,
    /// The job channel for the task driver is closed
    #[error("job queue closed")]
    JobQueueClosed,
    /// A task was preempted while running
    #[error("task was preempted while running")]
    Preempted,
    /// An error querying global state
    #[error("state error: {0}")]
    State(String),
    /// An error running a task
    #[error("task error: {0}")]
    TaskError(String),
}

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
