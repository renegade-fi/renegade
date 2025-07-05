//! Error types emitted by the state applicator

use std::{error::Error, fmt::Display};

use common::types::{tasks::TaskQueueKey, wallet::WalletIdentifier};

use crate::storage::error::StorageError;

/// The error type emitted by the storage applicator
#[derive(Debug)]
pub enum StateApplicatorError {
    /// An error enqueueing a task
    EnqueueTask(String),
    /// Missing keys in the database necessary for a tx
    MissingEntry(&'static str),
    /// An error indicating a state transition has been rejected
    ///
    /// This error will be sent directly to the listeners on a proposal and not
    /// forwarded to the raft core
    Rejected(String),
    /// An error interacting with storage
    Storage(StorageError),
    /// A task queue is empty when it should not be
    TaskQueueEmpty(TaskQueueKey),
    /// An error parsing a message separately from proto errors
    Parse(String),
    /// An error trying to preempt a committed task
    Preemption,
    /// An error updating a task state when a queue is paused
    QueuePaused(WalletIdentifier),
}

impl StateApplicatorError {
    /// Build a rejection message
    #[allow(clippy::needless_pass_by_value)]
    pub fn reject<T: ToString>(msg: T) -> Self {
        Self::Rejected(msg.to_string())
    }
}

impl Display for StateApplicatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for StateApplicatorError {}

impl From<StorageError> for StateApplicatorError {
    fn from(value: StorageError) -> Self {
        match value {
            StorageError::Rejected(msg) => Self::reject(msg),
            _ => Self::Storage(value),
        }
    }
}
