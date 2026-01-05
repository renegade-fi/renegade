use darkpool_types::{bounded_match_result::BoundedMatchResult, fee::FeeTake};
use serde::{Deserialize, Serialize};
use types_core::{AccountId, TimestampedPrice};
use types_account::IntentIdentifier;

/// A fill event on an order, resulting from an external match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalFillEvent {
    /// The ID of the internal wallet containing the filled order
    pub internal_account_id: AccountId,
    /// The ID of the internal order that received the fill
    pub internal_order_id: IntentIdentifier,
    /// The price at which the fill was executed
    pub execution_price: TimestampedPrice,
    /// The external match result
    pub external_match_result: BoundedMatchResult,
    /// The fees paid by the internal party as a result of the fill
    pub internal_fee_take: FeeTake,
}

impl ExternalFillEvent {
    /// Creates a new external fill event
    pub fn new(
        internal_account_id: AccountId,
        internal_order_id: IntentIdentifier,
        execution_price: TimestampedPrice,
        external_match_result: BoundedMatchResult,
        internal_fee_take: FeeTake,
    ) -> Self {
        Self {
            internal_account_id,
            internal_order_id,
            execution_price,
            external_match_result,
            internal_fee_take,
        }
    }

    /// Returns a human-readable description of the event
    pub fn describe(&self) -> String {
        "ExternalFill".to_string()
    }
}
