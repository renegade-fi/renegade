use serde::{Deserialize, Serialize};
use types_core::AccountId;

/// A wallet creation event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountCreationEvent {
    /// The ID of the account that was created
    pub account_id: AccountId,
    /// The wallet's symmetric key, base64-encoded
    pub symmetric_key: String,
}

impl AccountCreationEvent {
    /// Creates a new wallet creation event
    pub fn new(account_id: AccountId, symmetric_key: String) -> Self {
        Self { account_id, symmetric_key }
    }

    /// Returns a human-readable description of the event
    pub fn describe(&self) -> String {
        "AccountCreation".to_string()
    }
}
