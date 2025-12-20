//! Error types and conversions for the replication interface
use std::{
    fmt::Debug,
    io::{Error as IoError, ErrorKind as IoErrorKind},
};

use openraft::{
    ErrorSubject, ErrorVerb, LogId, RaftTypeConfig, StorageError as RaftStorageError,
    error::{NetworkError, RPCError, RaftError},
};

use crate::storage::error::StorageError;

use super::{Node, NodeId, TypeConfig};

/// Convert a storage error reading logs into a raft error
pub fn new_log_read_error(
    err: StorageError,
) -> RaftStorageError<<TypeConfig as RaftTypeConfig>::NodeId> {
    let io_err = IoError::new(IoErrorKind::Other, Box::new(err));
    RaftStorageError::from_io_error(ErrorSubject::Logs, ErrorVerb::Read, io_err)
}

/// Convert a storage error writing logs into a raft error
pub fn new_log_write_error(
    err: StorageError,
) -> RaftStorageError<<TypeConfig as RaftTypeConfig>::NodeId> {
    let io_err = IoError::new(IoErrorKind::Other, Box::new(err));
    RaftStorageError::from_io_error(ErrorSubject::Logs, ErrorVerb::Write, io_err)
}

/// Convert an error applying a log into a raft error
#[allow(clippy::needless_pass_by_value)]
pub fn new_apply_error<T: ToString>(
    log_id: LogId<NodeId>,
    err: T,
) -> RaftStorageError<<TypeConfig as RaftTypeConfig>::NodeId> {
    let io_err = IoError::new(IoErrorKind::Other, err.to_string());
    RaftStorageError::from_io_error(ErrorSubject::Apply(log_id), ErrorVerb::Write, io_err)
}

/// Convert a snapshot error to a raft error
pub fn new_snapshot_error(
    err: ReplicationError,
) -> RaftStorageError<<TypeConfig as RaftTypeConfig>::NodeId> {
    let io_err = IoError::new(IoErrorKind::Other, Box::new(err));
    RaftStorageError::from_io_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, io_err)
}

/// Convert a replication error into a networking error
#[allow(clippy::needless_pass_by_value)]
pub fn new_network_error(err: ReplicationError) -> RPCError<NodeId, Node, RaftError<NodeId>> {
    RPCError::Network(NetworkError::new(&err))
}

/// The error type emitted by the replication interface
#[derive(Debug, thiserror::Error)]
pub enum ReplicationError {
    /// An error deserializing a raft request/response
    #[error("error deserializing raft request/response: {0}")]
    Deserialize(String),
    /// An error proposing a state transition
    #[error("error proposing state transition: {0}")]
    Proposal(String),
    /// A generic raft error
    #[error("raft error: {0}")]
    Raft(String),
    /// An error setting up a raft
    #[error("error setting up raft: {0}")]
    RaftSetup(String),
    /// An error tearing down a raft
    #[error("error tearing down raft: {0}")]
    RaftTeardown(String),
    /// An error occurred while snapshotting
    #[error("error snapshotting: {0}")]
    Snapshot(String),
    /// An error in storage
    #[error("storage error: {0}")]
    Storage(StorageError),
}

impl From<StorageError> for ReplicationError {
    fn from(value: StorageError) -> Self {
        ReplicationError::Storage(value)
    }
}

impl<E: Debug> From<RaftError<NodeId, E>> for ReplicationError {
    fn from(value: RaftError<NodeId, E>) -> Self {
        ReplicationError::Raft(format!("{value:?}"))
    }
}
