//! Error types for task operations

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error type for task operations
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Error)]
pub enum TaskError {
    /// An error related to descriptor operations
    #[error("Descriptor error: {0}")]
    Descriptor(String),
    /// A validation error
    #[error("validation error: {0}")]
    Validation(String),
}

impl TaskError {
    /// Create a new descriptor error
    #[allow(clippy::needless_pass_by_value)]
    pub fn descriptor<T: ToString>(msg: T) -> Self {
        Self::Descriptor(msg.to_string())
    }

    /// Create a new validation error
    #[allow(clippy::needless_pass_by_value)]
    pub fn validation<T: ToString>(msg: T) -> Self {
        Self::Validation(msg.to_string())
    }
}
