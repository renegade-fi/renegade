//! Caching of matchable amounts
//!
//! Specifically, we build an efficiently queryable mapping from (pair, side) ->
//! matchable_amount
//!
//! This allows admin endpoints to efficiently query the matchable amount for a
//! given pair and side.
//!
//! This only caches externally enabled matchable amounts.

use std::collections::HashMap;

use circuit_types::{order::OrderSide, Amount};
use common::types::wallet::Pair;
use tokio::sync::RwLock;

use super::RwLockHashMap;

/// A mapping from pair -> side -> matchable amount
#[derive(Default)]
pub struct MatchableAmountMap {
    /// The mapping from pair -> side -> matchable amount
    ///
    /// This is used to efficiently query the matchable amount for a given pair
    /// and side
    matchable_amount_map: RwLockHashMap<(Pair, OrderSide), Amount>,
}

impl MatchableAmountMap {
    /// Construct a new matchable amount map
    pub fn new() -> Self {
        Self { matchable_amount_map: RwLock::new(HashMap::new()) }
    }

    // --- Getters --- //

    /// Get the matchable amount for a given pair and side
    pub async fn get(&self, pair: Pair, side: OrderSide) -> Amount {
        let matchable_amount_map = self.matchable_amount_map.read().await;
        let amount = matchable_amount_map.get(&(pair, side)).unwrap_or(&0);
        *amount
    }

    // --- Setters --- //

    /// Update the matchable amount for a given pair and side
    ///
    /// This method handles both increasing and decreasing the cached amount.
    /// It accounts for:
    /// - Order creation (previous = 0)
    /// - Order cancellation (new = 0)
    /// - Updates where matchable amount changes
    pub async fn update_amount(&self, pair: Pair, side: OrderSide, previous: Amount, new: Amount) {
        let mut amount_map = self.matchable_amount_map.write().await;
        let cached_amount = amount_map.entry((pair, side)).or_insert(0);
        if new >= previous {
            *cached_amount += new - previous;
        } else {
            *cached_amount = cached_amount.saturating_sub(previous - new);
        }
    }
}
