//! Defines error types emitted by the replication layer

use raft::{Error as RaftError, StorageError as RaftStorageError};
use std::{error::Error, fmt::Display};

use crate::storage::error::StorageError;

/// The error type emitted by the replication layer
#[derive(Debug)]
pub enum ReplicationError {
    /// A value was not found in storage
    EntryNotFound,
    /// Error parsing a stored value
    ParseValue(String),
    /// An error interacting with storage
    Storage(StorageError),
}

impl Display for ReplicationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for ReplicationError {}

impl From<ReplicationError> for RaftError {
    fn from(value: ReplicationError) -> Self {
        match value {
            ReplicationError::EntryNotFound => RaftError::Store(RaftStorageError::Unavailable),
            ReplicationError::Storage(e) => e.into(),
            ReplicationError::ParseValue(s) => RaftError::Store(RaftStorageError::Other(Box::new(
                ReplicationError::ParseValue(s),
            ))),
        }
    }
}