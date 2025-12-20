//! Error types emitted by the state applicator

use common::types::tasks::TaskQueueKey;

use crate::storage::error::StorageError;

/// The error type emitted by the storage applicator
#[derive(Debug, thiserror::Error)]
pub enum StateApplicatorError {
    /// An error enqueueing a task
    #[error("error enqueuing task: {0}")]
    EnqueueTask(String),
    /// Missing keys in the database necessary for a tx
    #[error("missing database entry: {0}")]
    MissingEntry(&'static str),
    /// An error indicating a state transition has been rejected
    ///
    /// This error will be sent directly to the listeners on a proposal and not
    /// forwarded to the raft core
    #[error("state transition rejected: {0}")]
    Rejected(String),
    /// An error interacting with storage
    #[error("storage error: {0}")]
    Storage(StorageError),
    /// A task queue is empty when it should not be
    #[error("queue {0} is empty, but should not be")]
    TaskQueueEmpty(TaskQueueKey),
}

impl StateApplicatorError {
    /// Build a rejection message
    #[allow(clippy::needless_pass_by_value)]
    pub fn reject<T: ToString>(msg: T) -> Self {
        Self::Rejected(msg.to_string())
    }
}

impl From<StorageError> for StateApplicatorError {
    fn from(value: StorageError) -> Self {
        match value {
            StorageError::Rejected(msg) => Self::reject(msg),
            _ => Self::Storage(value),
        }
    }
}
