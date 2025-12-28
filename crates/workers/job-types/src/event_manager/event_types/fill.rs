use darkpool_types::{fee::FeeTake, settlement_obligation::SettlementObligation};
use serde::{Deserialize, Serialize};
use types_core::{AccountId, TimestampedPrice};
use types_wallet::wallet::IntentIdentifier;

/// A fill event on an order, resulting from an internal match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FillEvent {
    /// The ID of the wallet containing the filled order
    pub account_id: AccountId,
    /// The ID of the order that received the fill
    pub order_id: IntentIdentifier,
    /// The price at which the fill was executed
    pub execution_price: TimestampedPrice,
    /// The settlement obligation
    pub obligation: SettlementObligation,
    /// The fees paid as a result of the fill
    pub fee_take: FeeTake,
}

impl FillEvent {
    /// Creates a new fill event
    pub fn new(
        account_id: AccountId,
        order_id: IntentIdentifier,
        execution_price: TimestampedPrice,
        obligation: SettlementObligation,
        fee_take: FeeTake,
    ) -> Self {
        Self { account_id, order_id, execution_price, obligation, fee_take }
    }

    /// Returns a human-readable description of the event
    pub fn describe(&self) -> String {
        "Fill".to_string()
    }
}
