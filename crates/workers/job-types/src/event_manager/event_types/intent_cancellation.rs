use circuit_types::Amount;
use darkpool_types::intent::Intent;
use serde::{Deserialize, Serialize};
use types_account::account::IntentIdentifier;
use types_core::AccountId;

/// An intent cancellation event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentCancellationEvent {
    /// The ID of the account that cancelled the intent
    pub account_id: AccountId,
    /// The ID of the intent that was cancelled
    pub intent_id: IntentIdentifier,
    /// The cancelled intent
    pub intent: Intent,
    /// The remaining amount of the base asset in the intent
    pub amount_remaining: Amount,
    /// The filled amount of the base asset in the intent
    pub amount_filled: Amount,
}

impl IntentCancellationEvent {
    /// Creates a new intent cancellation event
    pub fn new(
        account_id: AccountId,
        intent_id: IntentIdentifier,
        intent: Intent,
        amount_remaining: Amount,
        amount_filled: Amount,
    ) -> Self {
        Self { account_id, intent_id, intent, amount_remaining, amount_filled }
    }

    /// Returns a human-readable description of the event
    pub fn describe(&self) -> String {
        "IntentCancellation".to_string()
    }
}
