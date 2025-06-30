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

use circuit_types::{Amount, order::OrderSide};
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

    /// Get the matchable amount for both sides of a pair
    ///
    /// Returns (buy_amount, sell_amount) where buy amount is denominated in the
    /// quote token, sell amount is denominated in the base token
    pub async fn get(&self, pair: &Pair) -> (Amount, Amount) {
        let matchable_amount_map = self.matchable_amount_map.read().await;
        let buy_amount =
            matchable_amount_map.get(&(pair.clone(), OrderSide::Buy)).copied().unwrap_or(0);
        let sell_amount =
            matchable_amount_map.get(&(pair.clone(), OrderSide::Sell)).copied().unwrap_or(0);
        (buy_amount, sell_amount)
    }

    // --- Setters --- //

    /// Add to the matchable amount for a given pair and side
    pub async fn add_amount(&self, pair: Pair, side: OrderSide, delta: Amount) {
        let mut amount_map = self.matchable_amount_map.write().await;
        let cached_amount = amount_map.entry((pair, side)).or_insert(0);
        *cached_amount += delta;
    }

    /// Subtract from the matchable amount for a given pair and side
    pub async fn sub_amount(&self, pair: Pair, side: OrderSide, delta: Amount) {
        let mut amount_map = self.matchable_amount_map.write().await;
        let cached_amount = amount_map.entry((pair, side)).or_insert(0);
        *cached_amount = cached_amount.saturating_sub(delta);
    }
}
