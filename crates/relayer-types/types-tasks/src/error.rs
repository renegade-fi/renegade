//! Error types for task operations

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error type for task operations
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Error)]
pub enum TaskError {
    /// An error related to descriptor operations
    #[error("Descriptor error: {0}")]
    Descriptor(String),
    /// An order auth validation error
    #[error("Order auth validation error: {0}")]
    OrderAuthValidation(String),
}

impl TaskError {
    /// Create a new descriptor error
    #[allow(clippy::needless_pass_by_value)]
    pub fn descriptor<T: ToString>(msg: T) -> Self {
        Self::Descriptor(msg.to_string())
    }

    /// Create a new order auth validation error
    #[allow(clippy::needless_pass_by_value)]
    pub fn order_auth_validation<T: ToString>(msg: T) -> Self {
        Self::OrderAuthValidation(msg.to_string())
    }
}
