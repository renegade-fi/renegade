//! Error types emitted by the state applicator

use std::{error::Error, fmt::Display};

use state_proto::error::StateProtoError;

use crate::storage::error::StorageError;

/// The error type emitted by the storage applicator
#[derive(Debug)]
pub enum StateApplicatorError {
    /// An error interacting with storage
    Storage(StorageError),
    /// An error parsing a message separately from proto errors
    Parse(String),
    /// An error processing a proto
    Proto(StateProtoError),
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
