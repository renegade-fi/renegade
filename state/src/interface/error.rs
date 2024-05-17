//! Error types emitted in the state interface

use core::fmt::Display;
use std::error::Error;

use system_clock::SystemClockError;

use crate::{
    applicator::error::StateApplicatorError, replicationv2::error::ReplicationV2Error,
    storage::error::StorageError,
};

/// The state error type
#[derive(Debug)]
pub enum StateError {
    /// An error in the state applicator
    Applicator(StateApplicatorError),
    /// An error with the system clock
    Clock(SystemClockError),
    /// A database error
    Db(StorageError),
    /// Invalid state update passed to the interface
    InvalidUpdate(String),
    /// An error sending a proposal to the replication layer
    Proposal(String),
    /// An error in the replication substrate
    Replication(ReplicationV2Error),
    /// An error awaiting a runtime task
    Runtime(String),
    /// An error deserializing a message
    Serde(String),
}

impl Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for StateError {}

impl From<StorageError> for StateError {
    fn from(e: StorageError) -> Self {
        StateError::Db(e)
    }
}

/// Useful for error types expecting `String`
impl From<StateError> for String {
    fn from(e: StateError) -> Self {
        e.to_string()
    }
}

impl From<ReplicationV2Error> for StateError {
    fn from(e: ReplicationV2Error) -> Self {
        StateError::Replication(e)
    }
}
