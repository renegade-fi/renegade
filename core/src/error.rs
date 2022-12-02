//! Groups top-level errors useful throughout the relayer

use std::error::Error;
use std::fmt::Display;

/// An error type at the coordinator level
#[derive(Clone, Debug)]
pub enum CoordinatorError {
    /// Error attemting to recover a failed worker
    Recovery(String),
    /// Failure to send a cancel signal to a worker
    CancelSend(String),
    /// Failure to parse config correctly
    ConfigParse(String),
}

impl Error for CoordinatorError {}
impl Display for CoordinatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
