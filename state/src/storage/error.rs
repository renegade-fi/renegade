//! Error types for storage access

use libmdbx::Error as MdbxError;

/// The error type emitted by the storage layer
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Error creating a new transaction in the database
    #[error("error creating tx: {0}")]
    BeginTx(#[from] MdbxError),
    /// Error committing a transaction
    #[error("error committing tx: {0}")]
    Commit(MdbxError),
    /// Error deserializing a value from storage
    #[error("error deserializing value: {0}")]
    Deserialization(String),
    /// An invalid key was used to access the database
    #[error("invalid key: {0}")]
    InvalidKey(String),
    /// An entry was not found in the database
    #[error("entry not found: {0}")]
    NotFound(String),
    /// Failure opening the database
    #[error("error opening db: {0}")]
    OpenDb(MdbxError),
    /// Failure opening a table in the database
    #[error("error opening table: {0}")]
    OpenTable(MdbxError),
    /// Attempt to access a disabled table, which may be the case if it is
    /// used to track state for a feature that is disabled in the relayer.
    /// An example of this is the order history table being disabled if the
    /// relayer is not configured to record historical state.
    #[error("table disabled: {0}")]
    TableDisabled(String),
    /// An uncategorized error
    #[error("other error: {0}")]
    Other(String),
    /// Error serializing a value for storage
    #[error("error serializing value: {0}")]
    Serialization(String),
    /// Error syncing the database
    #[error("error syncing db: {0}")]
    Sync(MdbxError),
    /// Error while performing a transaction operation
    #[error("error performing tx op: {0}")]
    TxOp(MdbxError),
}

impl StorageError {
    /// Create a new `NotFound` error
    #[allow(clippy::needless_pass_by_value)]
    pub fn not_found<T: ToString>(msg: T) -> Self {
        Self::NotFound(msg.to_string())
    }

    /// Create a new `Other` error
    #[allow(clippy::needless_pass_by_value)]
    pub fn other<T: ToString>(msg: T) -> Self {
        Self::Other(msg.to_string())
    }
}
