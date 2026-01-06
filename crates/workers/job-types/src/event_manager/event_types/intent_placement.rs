use darkpool_types::intent::Intent;
use serde::{Deserialize, Serialize};
use types_account::{MatchingPoolName, OrderId};
use types_core::AccountId;

/// An intent placement event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentPlacementEvent {
    /// The ID of the wallet that placed the intent
    pub account_id: AccountId,
    /// The ID of the intent that was placed
    pub intent_id: OrderId,
    /// The placed intent
    pub intent: Intent,
    /// The matching pool to which the intent was assigned
    pub matching_pool: MatchingPoolName,
}

impl IntentPlacementEvent {
    /// Creates a new intent placement event
    pub fn new(
        account_id: AccountId,
        intent_id: OrderId,
        intent: Intent,
        matching_pool: MatchingPoolName,
    ) -> Self {
        Self { account_id, intent_id, intent, matching_pool }
    }

    /// Returns a human-readable description of the event
    pub fn describe(&self) -> String {
        "IntentPlacement".to_string()
    }
}
