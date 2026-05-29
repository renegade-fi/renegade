//! Error types emitted in the state interface

use system_clock::SystemClockError;

use crate::{
    applicator::error::StateApplicatorError, replication::error::ReplicationError,
    storage::error::StorageError, storage::tx::task_queue::storage::ERR_CANNOT_SERIALLY_PREEMPT,
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
    #[error("error serializing/deserializing: {0}")]
    Serde(String),
    /// A state transition was rejected
    #[error("state transition rejected: {0}")]
    TransitionRejected(String),
}

impl StateError {
    /// Create a new `Serde` error
    #[allow(clippy::needless_pass_by_value)]
    pub fn serde<T: ToString>(msg: T) -> Self {
        Self::Serde(msg.to_string())
    }

    /// Whether this error is the transient "serial preemption not allowed"
    /// reject — a settlement could not preempt a wallet queue because another
    /// serial (exclusive) task, or a committed task, holds it. This is expected
    /// under contention and is safe to retry (the reject itself is intentional;
    /// it guards committed settlements and prevents a two-wallet deadlock).
    pub fn is_serial_preemption_conflict(&self) -> bool {
        matches!(self, StateError::TransitionRejected(msg) if msg.contains(ERR_CANNOT_SERIALLY_PREEMPT))
    }
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

impl From<StateApplicatorError> for StateError {
    fn from(e: StateApplicatorError) -> Self {
        StateError::Applicator(e)
    }
}

#[cfg(test)]
mod preemption_conflict_test {
    use super::StateError;

    #[test]
    fn test_is_serial_preemption_conflict() {
        let conflict = StateError::TransitionRejected("serial preemption not allowed".to_string());
        assert!(conflict.is_serial_preemption_conflict());

        let other_reject = StateError::TransitionRejected("nullifier spent".to_string());
        assert!(!other_reject.is_serial_preemption_conflict());

        let unrelated = StateError::Proposal("raft down".to_string());
        assert!(!unrelated.is_serial_preemption_conflict());
    }
}
