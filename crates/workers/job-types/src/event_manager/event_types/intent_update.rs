use darkpool_types::intent::Intent;
use serde::{Deserialize, Serialize};
use types_core::AccountId;
use types_wallet::{MatchingPoolName, wallet::IntentIdentifier};

/// An intent update event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentUpdateEvent {
    /// The ID of the account that updated the intent
    pub account_id: AccountId,
    /// The ID of the intent that was updated
    pub intent_id: IntentIdentifier,
    /// The updated intent
    pub intent: Intent,
    /// The matching pool to which the intent was assigned
    pub matching_pool: MatchingPoolName,
}

impl IntentUpdateEvent {
    /// Creates a new intent update event
    pub fn new(
        account_id: AccountId,
        intent_id: IntentIdentifier,
        intent: Intent,
        matching_pool: MatchingPoolName,
    ) -> Self {
        Self { account_id, intent_id, intent, matching_pool }
    }

    /// Returns a human-readable description of the event
    pub fn describe(&self) -> String {
        "IntentUpdate".to_string()
    }
}
