//! Defines error types emitted during the course of the proof generation
//! module's execution

use thiserror::Error;

/// The abstract error type the proof manager emits
#[derive(Clone, Debug, Error)]
pub enum ProofManagerError {
    /// The coordinator cancelled the proof manager's execution
    #[error("proof manager cancelled: {0}")]
    Cancelled(String),
    /// An HTTP error
    #[error("HTTP error: {0}")]
    Http(String),
    /// The job queue has been closed, recv fails
    #[error("job queue closed: {0}")]
    JobQueueClosed(String),
    /// Error proving a statement
    #[error("error proving statement: {0}")]
    Prover(String),
    /// An error receiving on a channel
    #[error("error receiving on a channel: {0}")]
    RecvError(String),
    /// Error sending response to a proof job
    #[error("error sending response to proof job: {0}")]
    Response(String),
    /// Error setting up the proof generation manager
    #[error("error setting up the proof manager: {0}")]
    Setup(String),
}

impl ProofManagerError {
    /// Create an error from an HTTP error
    #[allow(clippy::needless_pass_by_value)]
    pub fn http<T: ToString>(err: T) -> Self {
        Self::Http(err.to_string())
    }

    /// Create an error from a prover error
    #[allow(clippy::needless_pass_by_value)]
    pub fn prover<T: ToString>(err: T) -> Self {
        Self::Prover(err.to_string())
    }

    /// Create a setup error
    #[allow(clippy::needless_pass_by_value)]
    pub fn setup<T: ToString>(err: T) -> Self {
        Self::Setup(err.to_string())
    }
}

impl From<reqwest::Error> for ProofManagerError {
    fn from(err: reqwest::Error) -> Self {
        Self::http(err)
    }
}
