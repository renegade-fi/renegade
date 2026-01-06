//! Caching of matchable amounts
//!
//! Specifically, we build an efficiently queryable mapping from (pair, side) ->
//! matchable_amount
//!
//! This allows admin endpoints to efficiently query the matchable amount for a
//! given pair and side.
//!
//! This only caches externally enabled matchable amounts.

use circuit_types::Amount;
use dashmap::DashMap;
use types_account::account::pair::Pair;

/// A mapping from pair -> side -> matchable amount
#[derive(Default)]
pub struct MatchableAmountMap {
    /// The mapping from pair -> side -> matchable amount
    ///
    /// This is used to efficiently query the matchable amount for a given pair
    /// and side
    matchable_amount_map: DashMap<Pair, Amount>,
}

impl MatchableAmountMap {
    /// Construct a new matchable amount map
    pub fn new() -> Self {
        Self { matchable_amount_map: DashMap::new() }
    }

    // --- Getters --- //

    /// Get the matchable amount for both sides of a pair
    ///
    /// Returns (buy_amount, sell_amount) where buy amount is denominated in the
    /// quote token, sell amount is denominated in the base token
    pub fn get(&self, pair: &Pair) -> (Amount, Amount) {
        let buy_amount = self.get_amount(pair);
        let sell_amount = self.get_amount(&pair.reverse());
        (buy_amount, sell_amount)
    }

    /// Get the matchable amount for a pair
    fn get_amount(&self, pair: &Pair) -> Amount {
        self.matchable_amount_map.get(pair).map(|a| *a.value()).unwrap_or_default()
    }

    // --- Setters --- //

    /// Add to the matchable amount for a given pair and side
    pub fn add_amount(&self, pair: Pair, delta: Amount) {
        let mut amt = self.matchable_amount_map.entry(pair).or_insert(0);
        *amt += delta;
    }

    /// Subtract from the matchable amount for a given pair and side
    pub fn sub_amount(&self, pair: Pair, delta: Amount) {
        let mut amt = self.matchable_amount_map.entry(pair).or_insert(0);
        *amt = amt.saturating_sub(delta);
    }
}
