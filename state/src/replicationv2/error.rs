//! Error types and conversions for the replication interface
use std::{
    error::Error,
    fmt::Display,
    io::{Error as IoError, ErrorKind as IoErrorKind},
};

use openraft::{
    error::{NetworkError, RPCError, RaftError},
    ErrorSubject, ErrorVerb, LogId, RaftTypeConfig, StorageError as RaftStorageError,
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
pub fn new_apply_error(
    log_id: LogId<NodeId>,
    err: String,
) -> RaftStorageError<<TypeConfig as RaftTypeConfig>::NodeId> {
    let io_err = IoError::new(IoErrorKind::Other, err);
    RaftStorageError::from_io_error(ErrorSubject::Apply(log_id), ErrorVerb::Write, io_err)
}

/// Convert a snapshot error to a raft error
pub fn new_snapshot_error(
    err: ReplicationV2Error,
) -> RaftStorageError<<TypeConfig as RaftTypeConfig>::NodeId> {
    let io_err = IoError::new(IoErrorKind::Other, Box::new(err));
    RaftStorageError::from_io_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, io_err)
}

/// Convert a replication error into a networking error
#[allow(clippy::needless_pass_by_value)]
pub fn new_network_error(err: ReplicationV2Error) -> RPCError<NodeId, Node, RaftError<NodeId>> {
    RPCError::Network(NetworkError::new(&err))
}

/// The error type emitted by the replication interface
///
/// TODO: Rename
#[derive(Debug)]
pub enum ReplicationV2Error {
    /// An error deserializing a raft response
    Deserialize(String),
    /// An error proposing a state transition
    Proposal(String),
    /// An error setting up a raft
    RaftSetup(String),
    /// An error tearing down a raft
    RaftTeardown(String),
    /// An error occurred while snapshotting
    Snapshot(String),
    /// An error in storage
    Storage(StorageError),
}

impl Display for ReplicationV2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplicationV2Error::Deserialize(e) => write!(f, "Deserialization error: {e}"),
            ReplicationV2Error::Proposal(e) => write!(f, "Proposal error: {e}"),
            ReplicationV2Error::RaftSetup(e) => write!(f, "Raft setup error: {e}"),
            ReplicationV2Error::RaftTeardown(e) => write!(f, "Raft teardown error: {e}"),
            ReplicationV2Error::Snapshot(e) => write!(f, "Snapshot error: {e}"),
            ReplicationV2Error::Storage(e) => write!(f, "Storage error: {e}"),
        }
    }
}
impl Error for ReplicationV2Error {}

impl From<StorageError> for ReplicationV2Error {
    fn from(value: StorageError) -> Self {
        ReplicationV2Error::Storage(value)
    }
}
