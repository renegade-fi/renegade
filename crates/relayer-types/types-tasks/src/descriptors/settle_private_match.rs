//! Descriptor for the settle private match task

use types_account::OrderId;
use types_core::MatchResult;
use types_core::{AccountId, TimestampedPriceFp};

use super::TaskDescriptor;

/// The task descriptor containing only the parameterization of the
/// `SettlePrivateMatch` task
///
/// This task settles a match using the `IntentAndBalancePrivateSettlement`
/// circuit, which generates a single proof covering both parties
/// simultaneously. This is used when both orders are in Ring 2 or Ring 3.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct SettlePrivateMatchTaskDescriptor {
    /// The account ID for the initiating order
    pub account_id: AccountId,
    /// The account ID for the counterparty order
    pub other_account_id: AccountId,
    /// The ID of the initiating order
    pub order_id: OrderId,
    /// The ID of the counterparty order
    pub other_order_id: OrderId,
    /// The price at which the match was executed
    pub execution_price: TimestampedPriceFp,
    /// The match result
    pub match_result: MatchResult,
}

impl From<SettlePrivateMatchTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: SettlePrivateMatchTaskDescriptor) -> Self {
        TaskDescriptor::SettlePrivateMatch(descriptor)
    }
}
