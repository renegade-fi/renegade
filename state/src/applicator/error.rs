//! Error types emitted by the state applicator

use std::{error::Error, fmt::Display};

use common::types::wallet::WalletIdentifier;

use crate::storage::error::StorageError;

/// The error type emitted by the storage applicator
#[derive(Debug)]
pub enum StateApplicatorError {
    /// An error enqueueing a task
    EnqueueTask(String),
    /// Missing keys in the database necessary for a tx
    MissingEntry(String),
    /// An error interacting with storage
    Storage(StorageError),
    /// An error parsing a message separately from proto errors
    Parse(String),
    /// An error trying to preempt a committed task
    Preemption,
    /// An error updating a task state when a queue is paused
    QueuePaused(WalletIdentifier),
}

impl Display for StateApplicatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for StateApplicatorError {}

impl From<StorageError> for StateApplicatorError {
    fn from(value: StorageError) -> Self {
        Self::Storage(value)
    }
}
