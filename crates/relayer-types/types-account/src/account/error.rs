//! Error types for account operations

use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};

/// Error type for account operations
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountError {
    /// An error related to balance operations
    Balance(String),
    /// An error related to order operations
    Order(String),
}

impl AccountError {
    /// Create a new balance error
    #[allow(clippy::needless_pass_by_value)]
    pub fn balance<T: ToString>(msg: T) -> Self {
        Self::Balance(msg.to_string())
    }

    /// Create a new order error
    #[allow(clippy::needless_pass_by_value)]
    pub fn order<T: ToString>(msg: T) -> Self {
        Self::Order(msg.to_string())
    }
}

impl Display for AccountError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            AccountError::Balance(msg) => write!(f, "Balance error: {msg}"),
            AccountError::Order(msg) => write!(f, "Order error: {msg}"),
        }
    }
}

impl Error for AccountError {}
