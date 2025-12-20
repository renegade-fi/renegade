//! Error types emitted in the state interface

use system_clock::SystemClockError;

use crate::{
    applicator::error::StateApplicatorError, replication::error::ReplicationError,
    storage::error::StorageError,
};

/// The state error type
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// An error in the state applicator
    #[error("state applicator error: {0}")]
    Applicator(StateApplicatorError),
    /// An error with the system clock
    #[error("system clock error: {0}")]
    Clock(SystemClockError),
    /// A database error
    #[error("database error: {0}")]
    Db(StorageError),
    /// Invalid state update passed to the interface
    #[error("invalid state update: {0}")]
    InvalidUpdate(String),
    /// An error sending a proposal to the replication layer
    #[error("error sending proposal to replication layer: {0}")]
    Proposal(String),
    /// An error in the replication substrate
    #[error("replication error: {0}")]
    Replication(ReplicationError),
    /// An error awaiting a runtime task
    #[error("error awaiting runtime task: {0}")]
    Runtime(String),
    /// An error deserializing a message
    #[error("error deserializing message: {0}")]
    Serde(String),
    /// A state transition was rejected
    #[error("state transition rejected: {0}")]
    TransitionRejected(String),
}

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

impl From<ReplicationError> for StateError {
    fn from(e: ReplicationError) -> Self {
        StateError::Replication(e)
    }
}
