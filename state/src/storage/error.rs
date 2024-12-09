//! Error types for storage access

use std::{error::Error, fmt::Display};

use libmdbx::Error as MdbxError;

/// The error type emitted by the storage layer
#[derive(Debug)]
pub enum StorageError {
    /// Error creating a new transaction in the database
    BeginTx(MdbxError),
    /// Error committing a transaction
    Commit(MdbxError),
    /// Error deserializing a value from storage
    Deserialization(String),
    /// An invalid key was used to access the database
    InvalidKey(String),
    /// An entry was not found in the database
    NotFound(String),
    /// Failure opening the database
    OpenDb(MdbxError),
    /// Failure opening a table in the database
    OpenTable(MdbxError),
    /// Attempt to access a disabled table, which may be the case if it is
    /// used to track state for a feature that is disabled in the relayer.
    /// An example of this is the order history table being disabled if the
    /// relayer is not configured to record historical state.
    TableDisabled(String),
    /// An uncategorized error
    Other(String),
    /// Error serializing a value for storage
    Serialization(String),
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
