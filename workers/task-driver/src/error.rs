//! Error types for the task driver

use std::error::Error;
use std::fmt::Display;

use crate::tasks::create_new_wallet::NewWalletTaskError;
use crate::tasks::lookup_wallet::LookupWalletTaskError;
use crate::tasks::settle_match::SettleMatchTaskError;
use crate::tasks::settle_match_internal::SettleMatchInternalTaskError;
use crate::tasks::update_merkle_proof::UpdateMerkleProofTaskError;
use crate::tasks::update_wallet::UpdateWalletTaskError;

/// The error type emitted by the task driver
#[derive(Clone, Debug)]
pub enum TaskDriverError {
    /// The job channel for the task driver is closed
    JobQueueClosed,
    /// An error running a task
    TaskError(String),
}

impl Display for TaskDriverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for TaskDriverError {}

impl From<NewWalletTaskError> for TaskDriverError {
    fn from(e: NewWalletTaskError) -> Self {
        TaskDriverError::TaskError(e.to_string())
    }
}

impl From<LookupWalletTaskError> for TaskDriverError {
    fn from(e: LookupWalletTaskError) -> Self {
        TaskDriverError::TaskError(e.to_string())
    }
}

impl From<SettleMatchInternalTaskError> for TaskDriverError {
    fn from(e: SettleMatchInternalTaskError) -> Self {
        TaskDriverError::TaskError(e.to_string())
    }
}

impl From<SettleMatchTaskError> for TaskDriverError {
    fn from(e: SettleMatchTaskError) -> Self {
        TaskDriverError::TaskError(e.to_string())
    }
}

impl From<UpdateWalletTaskError> for TaskDriverError {
    fn from(e: UpdateWalletTaskError) -> Self {
        TaskDriverError::TaskError(e.to_string())
    }
}

impl From<UpdateMerkleProofTaskError> for TaskDriverError {
    fn from(e: UpdateMerkleProofTaskError) -> Self {
        TaskDriverError::TaskError(e.to_string())
    }
}
