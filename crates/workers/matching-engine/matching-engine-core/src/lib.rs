//! Core matching engine logic
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![deny(unsafe_code)]

pub(crate) mod book;
pub(crate) mod engine;
use std::ops::RangeInclusive;

use circuit_types::Amount;
use darkpool_types::settlement_obligation::MatchResult;
pub use engine::MatchingEngine;
use types_account::OrderId;
use types_core::TimestampedPriceFp;

/// A successful match between two orders
pub struct SuccessfulMatch {
    /// The ID of the other order that matched
    pub other_order_id: OrderId,
    /// The price at which the match was executed
    pub price: TimestampedPriceFp,
    /// The match result
    pub match_result: MatchResult,
    /// The matchable amount bounds (min and max) for the counterparty order
    pub matchable_amount_bounds: RangeInclusive<Amount>,
}
