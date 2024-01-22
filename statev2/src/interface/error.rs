//! Error types emitted in the state interface

use core::fmt::Display;
use std::error::Error;

use crate::{replication::error::ReplicationError, storage::error::StorageError};

/// The state error type
#[derive(Debug)]
pub enum StateError {
    /// A database error
    Db(StorageError),
    /// An error sending a proposal to the replication layer
    Proposal(String),
    /// An error in the replication substrate
    Replication(ReplicationError),
}

impl Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for StateError {}
