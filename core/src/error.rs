//! Groups top-level errors useful throughout the relayer

use std::error::Error;
use std::fmt::Display;

#[derive(Clone, Debug)]
pub enum CoordinatorError {
    /// Error attemting to recover a failed worker
    RecoveryError(String),
    /// Failure to send a cancel signal to a worker
    CancelError(String),
}

impl Error for CoordinatorError {}
impl Display for CoordinatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
