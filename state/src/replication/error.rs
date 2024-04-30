//! Defines error types emitted by the replication layer

use raft::{Error as RaftError, StorageError as RaftStorageError};
use std::io::{Error as IOError, ErrorKind as IOErrorKind};
use std::{error::Error, fmt::Display};

use crate::applicator::error::StateApplicatorError;
use crate::storage::error::StorageError;

/// The error type emitted by the replication layer
#[derive(Debug)]
pub enum ReplicationError {
    /// An error originating from the `StateApplicator`
    Applicator(StateApplicatorError),
    /// Error applying a config change to the raft cluster
    ConfChange(String),
    /// A value was not found in storage
    EntryNotFound,
    /// Error parsing a stored value
    ParseValue(String),
    /// An error reading from the proposal queue
    ProposalQueue(String),
    /// An error from the raft library
    Raft(RaftError),
    /// An error receiving a message
    RecvMessage(IOError),
    /// An error sending a message
    SendMessage(IOError),
    /// An error sending a response to a proposal
    ProposalResponse(String),
    /// An error serializing a value
    SerializeValue(String),
    /// An error interacting with storage
    Storage(StorageError),
    /// An error setting up the raft node
    Setup(String),
}

impl Display for ReplicationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for ReplicationError {}

impl From<RaftError> for ReplicationError {
    fn from(value: RaftError) -> Self {
        Self::Raft(value)
    }
}

impl From<ReplicationError> for RaftError {
    fn from(value: ReplicationError) -> Self {
        match value {
            ReplicationError::Applicator(_)
            | ReplicationError::ProposalQueue(_)
            | ReplicationError::SerializeValue(_) => RaftError::ProposalDropped,
            ReplicationError::ConfChange(e) => RaftError::ConfChangeError(e.to_string()),
            ReplicationError::EntryNotFound => RaftError::Store(RaftStorageError::Unavailable),
            ReplicationError::Raft(e) => e,
            ReplicationError::Storage(e) => e.into(),
            ReplicationError::ParseValue(s) => {
                RaftError::Store(RaftStorageError::Other(Box::new(ReplicationError::ParseValue(s))))
            },
            ReplicationError::SendMessage(e) | ReplicationError::RecvMessage(e) => RaftError::Io(e),
            ReplicationError::ProposalResponse(e) => {
                RaftError::Io(IOError::new(IOErrorKind::Other, e))
            },
            ReplicationError::Setup(e) => RaftError::ConfigInvalid(e),
        }
    }
}

impl From<StorageError> for ReplicationError {
    fn from(value: StorageError) -> Self {
        Self::Storage(value)
    }
}
