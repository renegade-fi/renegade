//! Error types for storage access

use std::{error::Error, fmt::Display};

use bincode::Error as BincodeError;
use libmdbx::Error as MdbxError;
use raft::{Error as RaftError, StorageError as RaftStorageError};

/// The error type emitted by the storage layer
#[derive(Debug)]
pub enum StorageError {
    /// Error creating a new transaction in the database
    BeginTx(MdbxError),
    /// Error committing a transaction
    Commit(MdbxError),
    /// Error deserializing a value from storage
    Deserialization(BincodeError),
    /// An invalid key was used to access the database
    InvalidKey(String),
    /// An entry was not found in the database
    NotFound(String),
    /// Failure opening the database
    OpenDb(MdbxError),
    /// Failure opening a table in the database
    OpenTable(MdbxError),
    /// An uncategorized error
    Other(String),
    /// Error serializing a value for storage
    Serialization(BincodeError),
    /// Error syncing the database
    Sync(MdbxError),
    /// Error while performing a transaction operation
    TxOp(MdbxError),
}

impl Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StorageError: {self:?}")
    }
}

impl Error for StorageError {}

impl From<StorageError> for RaftError {
    fn from(value: StorageError) -> Self {
        RaftError::Store(RaftStorageError::Other(Box::new(value)))
    }
}
