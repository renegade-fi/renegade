//! Error types and conversions for the replication interface
use openraft::{ErrorSubject, ErrorVerb, LogId, RaftTypeConfig, StorageError as RaftStorageError};
use std::io::{Error as IoError, ErrorKind as IoErrorKind};

use crate::{applicator::error::StateApplicatorError, storage::error::StorageError};

use super::{NodeId, TypeConfig};

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
    err: StateApplicatorError,
) -> RaftStorageError<<TypeConfig as RaftTypeConfig>::NodeId> {
    let io_err = IoError::new(IoErrorKind::Other, Box::new(err));
    RaftStorageError::from_io_error(ErrorSubject::Apply(log_id), ErrorVerb::Write, io_err)
}
