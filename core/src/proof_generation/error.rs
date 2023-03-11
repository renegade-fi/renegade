//! Defines error types emitted during the course of the proof generation module's execution

use std::fmt::{Display, Formatter, Result as FmtResult};

/// The abstract error type the proof manager emits
#[derive(Clone, Debug)]
pub enum ProofManagerError {
    /// The coordinator cancelled the proof manager's execution
    Cancelled(String),
    /// The job queue has been closed, recv fails
    JobQueueClosed(String),
    /// Error proving a statement
    Prover(String),
    /// An error receiving on a channel
    RecvError(String),
    /// Error sending response along a job's response channel
    Response(String),
    /// Error setting up the proof generation manager
    Setup(String),
}

impl Display for ProofManagerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{:?}", self)
    }
}
