//! The matching engine

use std::{ops::RangeInclusive, sync::Arc};

use circuit_types::{Amount, fixed_point::FixedPoint};
use crypto::fields::scalar_to_u128;
use darkpool_types::settlement_obligation::SettlementObligation;
use dashmap::DashMap;
use types_account::{MatchingPoolName, order::Order, order::PrivacyRing, pair::Pair};
use types_core::AccountId;
use types_core::MatchResult;
use types_core::TimestampedPriceFp;

use crate::{SuccessfulMatch, book::Book};

/// The matching engine
#[derive(Clone)]
pub struct MatchingEngine {
    /// A mapping from asset pair and matching pool to the book
    book_map: Arc<DashMap<(Pair, MatchingPoolName), Book>>,
    /// A book containing all orders across all pools, keyed by pair
    ///
    /// This is used for external matching when no specific pool is specified,
    /// allowing external matches to find the best counterparty across all
    /// pools.
    all_pools_book: Arc<DashMap<Pair, Book>>,
}

impl Default for MatchingEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl MatchingEngine {
    /// Create a new matching engine
    pub fn new() -> Self {
        Self { book_map: Arc::new(DashMap::new()), all_pools_book: Arc::new(DashMap::new()) }
    }

    // --- Order Operations --- //

    /// Whether the matching engine contains an order
    pub fn contains_order(&self, order: &Order, matching_pool: MatchingPoolName) -> bool {
        let pair = order.pair();
        if let Some(book) = self.book_map.get(&(pair, matching_pool)) {
            book.contains_order(order.id)
        } else {
            false
        }
    }

    /// Get the matchable amount for an order
    pub fn get_matchable_amount(
        &self,
        order: &Order,
        matching_pool: MatchingPoolName,
    ) -> Option<Amount> {
        let pair = order.pair();
        if let Some(book) = self.book_map.get(&(pair, matching_pool)) {
            book.get_matchable_amount(order.id)
        } else {
            None
        }
    }

    /// Add an order to the matching engine
    pub fn upsert_order(
        &self,
        account_id: AccountId,
        order: &Order,
        matchable_amount: Amount,
        matching_pool: MatchingPoolName,
    ) {
        let pair = order.pair();

        // Upsert into the pool-specific book
        let mut book = self.book_map.entry((pair, matching_pool)).or_insert_with(Book::new);
        if book.contains_order(order.id) {
            book.update_order(account_id, order, matchable_amount);
        } else {
            book.add_order(account_id, order, matchable_amount);
        }
        drop(book);

        // Upsert into the all-pools book
        let mut all_book = self.all_pools_book.entry(pair).or_insert_with(Book::new);
        if all_book.contains_order(order.id) {
            all_book.update_order(account_id, order, matchable_amount);
        } else {
            all_book.add_order(account_id, order, matchable_amount);
        }
    }

    /// Remove an order from the matching engine
    pub fn cancel_order(&self, order: &Order, matching_pool: MatchingPoolName) {
        let pair = order.pair();

        // Remove from the pool-specific book
        if let Some(mut book) = self.book_map.get_mut(&(pair, matching_pool)) {
            book.remove_order(order.id);
        }

        // Remove from the all-pools book
        if let Some(mut all_book) = self.all_pools_book.get_mut(&pair) {
            all_book.remove_order(order.id);
        }
    }

    /// Update the matchable amount for an order
    pub fn update_order(
        &self,
        account_id: AccountId,
        order: &Order,
        matchable_amount: Amount,
        matching_pool: MatchingPoolName,
    ) {
        let pair = order.pair();

        // Update in the pool-specific book
        if let Some(mut book) = self.book_map.get_mut(&(pair, matching_pool)) {
            book.update_order(account_id, order, matchable_amount);
        }

        // Update in the all-pools book
        if let Some(mut all_book) = self.all_pools_book.get_mut(&pair) {
            all_book.update_order(account_id, order, matchable_amount);
        }
    }

    /// Get the matchable amount for both sides of a pair
    ///
    /// Returns (buy_amount, sell_amount) where buy amount is denominated in the
    /// quote token, sell amount is denominated in the base token
    pub fn get_liquidity_for_pair(&self, _pair: &Pair) -> (Amount, Amount) {
        todo!("Implement get_liquidity_for_pair")
    }

    // --- Matching Operations --- //

    /// Find an internal match for an order
    ///
    /// Orders belonging to `exclude_account_id` will be skipped to prevent
    /// self-matches.
    ///
    /// The price here is specified in terms of the input order's output token /
    /// input token. I.e. it is in the same units as the input order's min
    /// price.
    ///
    /// In what follows, the input party is the party whose order is input to
    /// this method and the counterparty is the party whose order is discovered
    /// by walking the book.
    ///
    /// This method does not filter on externally matchable status.
    pub fn find_match(
        &self,
        exclude_account_id: AccountId,
        input_ring: PrivacyRing,
        input_pair: Pair,
        input_range: RangeInclusive<Amount>,
        matching_pool: MatchingPoolName,
        ts_price: TimestampedPriceFp,
    ) -> Option<SuccessfulMatch> {
        self.find_match_helper(
            exclude_account_id,
            input_ring,
            input_pair,
            input_range,
            matching_pool,
            ts_price,
            false,
        )
    }

    /// Find an external match for an order
    ///
    /// Orders belonging to `exclude_account_id` will be skipped. For external
    /// matches, pass a dummy/nil UUID since external parties have no account.
    ///
    /// The price here is specified in terms of the input order's output token /
    /// input token. I.e. it is in the same units as the input order's min
    /// price.
    ///
    /// In what follows, the input party is the party whose order is input to
    /// this method and the counterparty is the party whose order is discovered
    /// by walking the book.
    ///
    /// This method requires any order it matches against to have
    /// `externally_matchable` set to `true`.
    pub fn find_match_external(
        &self,
        input_ring: PrivacyRing,
        input_pair: Pair,
        input_range: RangeInclusive<Amount>,
        matching_pool: MatchingPoolName,
        ts_price: TimestampedPriceFp,
    ) -> Option<SuccessfulMatch> {
        // External matches have no internal account, so we use a dummy account ID
        let exclude_account_id = AccountId::nil();
        self.find_match_helper(
            exclude_account_id,
            input_ring,
            input_pair,
            input_range,
            matching_pool,
            ts_price,
            true,
        )
    }

    /// Find an external match for an order across all matching pools
    ///
    /// Orders belonging to `exclude_account_id` will be skipped. For external
    /// matches, pass a dummy/nil UUID since external parties have no account.
    ///
    /// This method searches the all-pools book which contains orders from every
    /// matching pool, allowing external matches to find the best counterparty
    /// regardless of which pool the order belongs to.
    ///
    /// The price here is specified in terms of the input order's output token /
    /// input token. I.e. it is in the same units as the input order's min
    /// price.
    ///
    /// This method requires any order it matches against to have
    /// `externally_matchable` set to `true`.
    pub fn find_match_external_all_pools(
        &self,
        input_ring: PrivacyRing,
        input_pair: Pair,
        input_range: RangeInclusive<Amount>,
        ts_price: TimestampedPriceFp,
    ) -> Option<SuccessfulMatch> {
        // External matches have no internal account, so no need to exclude
        // counterparties
        let exclude_account_id = AccountId::nil();

        // Build the book inputs
        let price = ts_price.price;
        let counterparty_pair = input_pair.reverse();
        let counterparty_price = price.inverse()?;
        let output_range = input_range_to_output_range(input_range, price);

        // Query the all-pools book instead of a pool-specific book
        let book = self.all_pools_book.get(&counterparty_pair)?;
        let (counterparty_oid, counterparty_input_amount, matchable_amount_bounds) = book
            .find_match(
                exclude_account_id,
                input_ring,
                counterparty_price,
                output_range,
                true, // require_externally_matchable
            )?;
        drop(book);

        // Build the match result
        self.build_match_result(
            input_pair,
            ts_price,
            counterparty_oid,
            counterparty_input_amount,
            matchable_amount_bounds,
        )
    }

    /// Common helper for finding matches
    ///
    /// Orders belonging to `exclude_account_id` will be skipped to prevent
    /// self-matches.
    ///
    /// The price here is specified in terms of the input order's output token /
    /// input token. I.e. it is in the same units as the input order's min
    /// price.
    ///
    /// In what follows, the input party is the party whose order is input to
    /// this method and the counterparty is the party whose order is discovered
    /// by walking the book.
    ///
    /// If `require_externally_matchable` is `true`, only matches against
    /// orders that have `externally_matchable` set to `true`. If `false`, does
    /// not filter on externally matchable status.
    #[allow(clippy::too_many_arguments)]
    fn find_match_helper(
        &self,
        exclude_account_id: AccountId,
        input_ring: PrivacyRing,
        input_pair: Pair,
        input_range: RangeInclusive<Amount>,
        matching_pool: MatchingPoolName,
        ts_price: TimestampedPriceFp,
        require_externally_matchable: bool,
    ) -> Option<SuccessfulMatch> {
        let price = ts_price.price;
        let counterparty_pair = input_pair.reverse();
        let counterparty_price = price.inverse()?;
        let output_range = input_range_to_output_range(input_range, price);

        let book = self.book_map.get(&(counterparty_pair, matching_pool))?;
        let (counterparty_oid, counterparty_input_amount, matchable_amount_bounds) = book
            .find_match(
                exclude_account_id,
                input_ring,
                counterparty_price,
                output_range,
                require_externally_matchable,
            )?;
        drop(book);

        self.build_match_result(
            input_pair,
            ts_price,
            counterparty_oid,
            counterparty_input_amount,
            matchable_amount_bounds,
        )
    }

    /// Build a `SuccessfulMatch` from the match parameters
    fn build_match_result(
        &self,
        input_pair: Pair,
        ts_price: TimestampedPriceFp,
        counterparty_oid: types_account::OrderId,
        counterparty_input_amount: Amount,
        matchable_amount_bounds: RangeInclusive<Amount>,
    ) -> Option<SuccessfulMatch> {
        let counterparty_price = ts_price.price.inverse()?;
        let input_amount_scalar = counterparty_price.floor_mul_int(counterparty_input_amount);
        let input_amount = scalar_to_u128(&input_amount_scalar);

        // The input party's obligation
        let obligation1 = SettlementObligation {
            input_token: input_pair.in_token,
            output_token: input_pair.out_token,
            amount_in: input_amount,
            amount_out: counterparty_input_amount,
        };

        // The counterparty's obligation
        let obligation2 = SettlementObligation {
            input_token: input_pair.out_token,
            output_token: input_pair.in_token,
            amount_in: counterparty_input_amount,
            amount_out: input_amount,
        };

        let match_result = MatchResult::new(obligation1, obligation2);
        Some(SuccessfulMatch {
            other_order_id: counterparty_oid,
            price: ts_price,
            match_result,
            matchable_amount_bounds,
        })
    }
}

// -----------
// | Helpers |
// -----------

/// Convert an input range to an output range
#[inline]
fn input_range_to_output_range(
    input_range: RangeInclusive<Amount>,
    price: FixedPoint,
) -> RangeInclusive<Amount> {
    let start = price.floor_mul_int(*input_range.start());
    let end = price.floor_mul_int(*input_range.end());
    scalar_to_u128(&start)..=scalar_to_u128(&end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;
    use types_account::{
        account::order::Order, order::PrivacyRing, order::mocks::mock_order_with_pair,
    };

    // -----------
    // | Helpers |
    // -----------

    /// Create a test pair
    fn test_pair() -> Pair {
        Pair::new(Address::from([1; 20]), Address::from([2; 20]))
    }

    /// Create a test order with the given matchable amount and min price
    fn create_test_order(matchable_amount: Amount, min_price: FixedPoint) -> Order {
        let mut order = mock_order_with_pair(test_pair());
        order.intent.inner.amount_in = matchable_amount * 2;
        order.intent.inner.min_price = min_price;
        order.metadata.min_fill_size = 1;
        order
    }

    /// Create a counterparty order (reversed pair) with the given matchable
    /// amount and min price
    fn create_counterparty_order(matchable_amount: Amount, min_price: FixedPoint) -> Order {
        let pair = test_pair();
        let mut order = mock_order_with_pair(pair.reverse());
        order.intent.inner.amount_in = matchable_amount * 2;
        order.intent.inner.min_price = min_price;
        order.metadata.min_fill_size = 1;
        order
    }

    /// Create a counterparty order with an explicit ring
    fn create_counterparty_order_with_ring(
        matchable_amount: Amount,
        min_price: FixedPoint,
        ring: PrivacyRing,
    ) -> Order {
        let mut order = create_counterparty_order(matchable_amount, min_price);
        order.ring = ring;
        order
    }

    fn test_matching_pool() -> MatchingPoolName {
        "test_pool".to_string()
    }

    // -------------------------
    // | Order Operation Tests |
    // -------------------------

    #[test]
    fn test_add_order() {
        let engine = MatchingEngine::new();
        let order = create_test_order(100, FixedPoint::from_integer(1));
        let pool = test_matching_pool();
        let account_id = AccountId::new_v4();

        engine.upsert_order(account_id, &order, 100, pool.clone());
        assert!(engine.contains_order(&order, pool.clone()));
    }

    #[test]
    fn test_cancel_order() {
        let engine = MatchingEngine::new();
        let order = create_test_order(100, FixedPoint::from_integer(1));
        let pool = test_matching_pool();
        let account_id = AccountId::new_v4();

        engine.upsert_order(account_id, &order, 100, pool.clone());
        engine.cancel_order(&order, pool.clone());
        assert!(!engine.contains_order(&order, pool.clone()));
    }

    #[test]
    fn test_cancel_nonexistent_order() {
        let engine = MatchingEngine::new();
        let order = create_test_order(100, FixedPoint::from_integer(1));
        let pool = test_matching_pool();

        // Should not panic
        engine.cancel_order(&order, pool.clone());
        assert!(!engine.contains_order(&order, pool));
    }

    #[test]
    fn test_update_nonexistent_order() {
        let engine = MatchingEngine::new();
        let order = create_test_order(100, FixedPoint::from_integer(1));
        let pool = test_matching_pool();
        let account_id = AccountId::new_v4();

        // Should not panic
        engine.update_order(account_id, &order, 200, pool);
    }

    // ------------------
    // | Matching Tests |
    // ------------------

    #[test]
    fn test_find_match_basic() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();
        let input_account_id = AccountId::new_v4();
        let counterparty_account_id = AccountId::new_v4();

        // Input order wants to trade token A -> token B
        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2); // 2 B per A
        let input_range = 0..=100; // Can provide up to 100 A

        // Counterparty order wants to trade token B -> token A
        // Their min_price is in units of A/B = 1/2 = 0.5
        let counterparty_order =
            create_counterparty_order(500, FixedPoint::from_f64_round_down(0.5));
        engine.upsert_order(counterparty_account_id, &counterparty_order, 500, pool.clone());

        let result = engine.find_match(
            input_account_id,
            PrivacyRing::Ring0,
            input_pair,
            input_range,
            pool,
            TimestampedPriceFp::from(price),
        );
        assert!(result.is_some(), "Should find a match");

        let successful_match = result.unwrap();
        assert_eq!(successful_match.other_order_id, counterparty_order.id);

        let ob1 = successful_match.match_result.party0_obligation();
        let ob2 = successful_match.match_result.party1_obligation();

        // Verify tokens are correct
        assert_eq!(ob1.input_token, input_pair.in_token);
        assert_eq!(ob1.output_token, input_pair.out_token);
        assert_eq!(ob2.input_token, input_pair.out_token);
        assert_eq!(ob2.output_token, input_pair.in_token);

        // Verify amounts are consistent
        assert_eq!(ob1.amount_out, ob2.amount_in);
        assert_eq!(ob1.amount_in, ob2.amount_out);

        // At price 2.0, 100 A should get 200 B
        assert_eq!(ob1.amount_in, 100);
        assert_eq!(ob1.amount_out, 200);
    }

    #[test]
    fn test_find_match_no_counterparty_orders() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();
        let account_id = AccountId::new_v4();

        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2);
        let input_range = 0..=100;

        let result = engine.find_match(
            account_id,
            PrivacyRing::Ring0,
            input_pair,
            input_range,
            pool,
            TimestampedPriceFp::from(price),
        );
        assert!(result.is_none(), "Should not find match when no counterparty orders exist");
    }

    #[test]
    fn test_find_match_price_too_low() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();
        let input_account_id = AccountId::new_v4();
        let counterparty_account_id = AccountId::new_v4();

        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2); // 2 B per A
        let input_range = 0..=100;

        // Counterparty wants at least 0.6 A per B (min_price = 0.6)
        // But at price 2.0, counterparty gets 0.5 A per B (inverse = 0.5)
        // So 0.5 < 0.6, match should fail
        let counterparty_order =
            create_counterparty_order(500, FixedPoint::from_f64_round_down(0.6));
        engine.upsert_order(counterparty_account_id, &counterparty_order, 500, pool.clone());

        let result = engine.find_match(
            input_account_id,
            PrivacyRing::Ring0,
            input_pair,
            input_range,
            pool,
            TimestampedPriceFp::from(price),
        );
        assert!(result.is_none(), "Should not match when price is below counterparty's min");
    }

    #[test]
    fn test_find_match_limited_by_max_input() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();
        let input_account_id = AccountId::new_v4();
        let counterparty_account_id = AccountId::new_v4();

        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2); // 2 B per A
        let input_range = 0..=50; // Limited to 50 A

        let counterparty_order =
            create_counterparty_order(500, FixedPoint::from_f64_round_down(0.4));
        engine.upsert_order(counterparty_account_id, &counterparty_order, 500, pool.clone());

        let result = engine.find_match(
            input_account_id,
            PrivacyRing::Ring0,
            input_pair,
            input_range,
            pool,
            TimestampedPriceFp::from(price),
        );
        assert!(result.is_some());

        let successful_match = result.unwrap();
        let ob1 = successful_match.match_result.party0_obligation();

        // Should be limited by input_range max: 50 A -> 100 B
        assert_eq!(ob1.amount_in, 50);
        assert_eq!(ob1.amount_out, 100);
    }

    #[test]
    fn test_find_match_limited_by_counterparty_amount() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();
        let input_account_id = AccountId::new_v4();
        let counterparty_account_id = AccountId::new_v4();

        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2); // 2 B per A
        let input_range = 0..=1000; // Can provide up to 1000 A

        // Counterparty only has 100 B available
        let counterparty_order =
            create_counterparty_order(100, FixedPoint::from_f64_round_down(0.4));
        engine.upsert_order(counterparty_account_id, &counterparty_order, 100, pool.clone());

        let result = engine.find_match(
            input_account_id,
            PrivacyRing::Ring0,
            input_pair,
            input_range,
            pool,
            TimestampedPriceFp::from(price),
        );
        assert!(result.is_some());

        let successful_match = result.unwrap();
        let ob1 = successful_match.match_result.party0_obligation();

        // Should be limited by counterparty's amount: 50 A -> 100 B
        assert_eq!(ob1.amount_in, 50);
        assert_eq!(ob1.amount_out, 100);
    }

    #[test]
    fn test_find_match_multiple_orders_selects_largest() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();
        let input_account_id = AccountId::new_v4();
        let counterparty_account_id = AccountId::new_v4();

        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2);
        let input_range = 0..=1000;

        // Add multiple counterparty orders with different matchable amounts
        let order1 = create_counterparty_order(100, FixedPoint::from_f64_round_down(0.4));
        let order2 = create_counterparty_order(500, FixedPoint::from_f64_round_down(0.4));
        let order3 = create_counterparty_order(200, FixedPoint::from_f64_round_down(0.4));

        engine.upsert_order(counterparty_account_id, &order1, 100, pool.clone());
        engine.upsert_order(counterparty_account_id, &order2, 500, pool.clone());
        engine.upsert_order(counterparty_account_id, &order3, 200, pool.clone());

        let result = engine.find_match(
            input_account_id,
            PrivacyRing::Ring0,
            input_pair,
            input_range,
            pool,
            TimestampedPriceFp::from(price),
        );
        assert!(result.is_some());

        // Should match with order2 (largest matchable amount = 500)
        let successful_match = result.unwrap();
        assert_eq!(successful_match.other_order_id, order2.id);

        // Should match 250 A -> 500 B (limited by counterparty's 500 B)
        let ob1 = successful_match.match_result.party0_obligation();
        assert_eq!(ob1.amount_in, 250);
        assert_eq!(ob1.amount_out, 500);
    }

    #[test]
    fn test_find_match_different_matching_pools() {
        let engine = MatchingEngine::new();
        let pool1 = "pool1".to_string();
        let pool2 = "pool2".to_string();
        let input_account_id = AccountId::new_v4();
        let counterparty_account_id = AccountId::new_v4();

        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2);
        let input_range = 0..=100;

        // Add order to pool1
        let order1 = create_counterparty_order(500, FixedPoint::from_f64_round_down(0.4));
        engine.upsert_order(counterparty_account_id, &order1, 500, pool1.clone());

        // Should find match in pool1
        let result1 = engine.find_match(
            input_account_id,
            PrivacyRing::Ring0,
            input_pair,
            input_range.clone(),
            pool1.clone(),
            TimestampedPriceFp::from(price),
        );
        assert!(result1.is_some());
        let successful_match1 = result1.unwrap();
        assert_eq!(successful_match1.other_order_id, order1.id);

        // Should not find match in pool2
        let result2 = engine.find_match(
            input_account_id,
            PrivacyRing::Ring0,
            input_pair,
            input_range,
            pool2,
            TimestampedPriceFp::from(price),
        );
        assert!(result2.is_none());
    }

    #[test]
    fn test_find_match_min_fill_size_constraint() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();
        let input_account_id = AccountId::new_v4();
        let counterparty_account_id = AccountId::new_v4();

        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2);
        let input_range = 0..=10; // Small amount

        // Counterparty has large min_fill_size
        let mut counterparty_order =
            create_counterparty_order(500, FixedPoint::from_f64_round_down(0.4));
        counterparty_order.metadata.min_fill_size = 100; // Requires at least 100 B
        engine.upsert_order(counterparty_account_id, &counterparty_order, 500, pool.clone());

        // input_range max of 10 A -> 20 B, but counterparty needs at least 100 B
        let result = engine.find_match(
            input_account_id,
            PrivacyRing::Ring0,
            input_pair,
            input_range,
            pool,
            TimestampedPriceFp::from(price),
        );
        assert!(result.is_none(), "Should not match when min_fill_size not met");
    }

    #[test]
    fn test_find_match_fractional_price() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();
        let input_account_id = AccountId::new_v4();
        let counterparty_account_id = AccountId::new_v4();

        let input_pair = test_pair();
        let price = FixedPoint::from_f64_round_down(1.5); // 1.5 B per A
        let input_range = 0..=100;

        let counterparty_order =
            create_counterparty_order(500, FixedPoint::from_f64_round_down(0.5));
        engine.upsert_order(counterparty_account_id, &counterparty_order, 500, pool.clone());

        let result = engine.find_match(
            input_account_id,
            PrivacyRing::Ring0,
            input_pair,
            input_range,
            pool,
            TimestampedPriceFp::from(price),
        );
        assert!(result.is_some());

        let successful_match = result.unwrap();
        let ob1 = successful_match.match_result.party0_obligation();

        // 100 A * 1.5 = 150 B
        // Due to floor rounding in fixed-point arithmetic, input amount is rounded down
        assert_eq!(ob1.amount_in, 99);
        assert_eq!(ob1.amount_out, 150);
    }

    #[test]
    fn test_find_match_ring3_rejects_ring0_and_ring1() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();
        let input_account_id = AccountId::new_v4();
        let counterparty_account_id = AccountId::new_v4();
        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2);
        let input_range = 0..=100;

        let ring0_order = create_counterparty_order_with_ring(
            400,
            FixedPoint::from_f64_round_down(0.4),
            PrivacyRing::Ring0,
        );
        let ring1_order = create_counterparty_order_with_ring(
            300,
            FixedPoint::from_f64_round_down(0.4),
            PrivacyRing::Ring1,
        );
        engine.upsert_order(counterparty_account_id, &ring0_order, 400, pool.clone());
        engine.upsert_order(counterparty_account_id, &ring1_order, 300, pool.clone());

        let result = engine.find_match(
            input_account_id,
            PrivacyRing::Ring3,
            input_pair,
            input_range,
            pool,
            TimestampedPriceFp::from(price),
        );
        assert!(result.is_none(), "Ring3 must not match Ring0/Ring1 counterparties");
    }

    #[test]
    fn test_find_match_ring3_accepts_ring2_and_ring3() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();
        let input_account_id = AccountId::new_v4();
        let counterparty_account_id = AccountId::new_v4();
        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2);
        let input_range = 0..=1000;

        let ring2_order = create_counterparty_order_with_ring(
            500,
            FixedPoint::from_f64_round_down(0.4),
            PrivacyRing::Ring2,
        );
        let ring3_order = create_counterparty_order_with_ring(
            300,
            FixedPoint::from_f64_round_down(0.4),
            PrivacyRing::Ring3,
        );
        engine.upsert_order(counterparty_account_id, &ring2_order, 500, pool.clone());
        engine.upsert_order(counterparty_account_id, &ring3_order, 300, pool.clone());

        let result = engine.find_match(
            input_account_id,
            PrivacyRing::Ring3,
            input_pair,
            input_range,
            pool,
            TimestampedPriceFp::from(price),
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().other_order_id, ring2_order.id);
    }

    #[test]
    fn test_find_match_ring2_can_match_all_rings() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();
        let input_account_id = AccountId::new_v4();
        let counterparty_account_id = AccountId::new_v4();
        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2);
        let input_range = 0..=1000;

        let ring0_order = create_counterparty_order_with_ring(
            600,
            FixedPoint::from_f64_round_down(0.4),
            PrivacyRing::Ring0,
        );
        let ring3_order = create_counterparty_order_with_ring(
            500,
            FixedPoint::from_f64_round_down(0.4),
            PrivacyRing::Ring3,
        );
        engine.upsert_order(counterparty_account_id, &ring0_order, 600, pool.clone());
        engine.upsert_order(counterparty_account_id, &ring3_order, 500, pool.clone());

        let result = engine.find_match(
            input_account_id,
            PrivacyRing::Ring2,
            input_pair,
            input_range,
            pool,
            TimestampedPriceFp::from(price),
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().other_order_id, ring0_order.id);
    }

    #[test]
    fn test_find_match_external_only_matches_externally_matchable() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();
        let input_account_id = AccountId::new_v4();
        let counterparty_account_id = AccountId::new_v4();

        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2); // 2 B per A
        let input_range = 0..=100;

        // Create two counterparty orders:
        // order1: externally matchable (default)
        // order2: not externally matchable
        let mut order1 = create_counterparty_order(500, FixedPoint::from_f64_round_down(0.4));
        order1.metadata.allow_external_matches = true;

        let mut order2 = create_counterparty_order(300, FixedPoint::from_f64_round_down(0.4));
        order2.metadata.allow_external_matches = false;

        engine.upsert_order(counterparty_account_id, &order1, 300, pool.clone());
        engine.upsert_order(counterparty_account_id, &order2, 500, pool.clone());

        // find_match (internal) should match with order2 (largest, 500)
        let result_internal = engine.find_match(
            input_account_id,
            PrivacyRing::Ring0,
            input_pair,
            input_range.clone(),
            pool.clone(),
            TimestampedPriceFp::from(price),
        );
        assert!(result_internal.is_some());
        let successful_match_internal = result_internal.unwrap();
        assert_eq!(
            successful_match_internal.other_order_id, order2.id,
            "Internal match should find order2 (largest)"
        );

        // find_match_external should match with order1 (only externally matchable)
        let result_external = engine.find_match_external(
            PrivacyRing::Ring0,
            input_pair,
            input_range,
            pool.clone(),
            TimestampedPriceFp::from(price),
        );
        assert!(result_external.is_some());
        let successful_match_external = result_external.unwrap();
        assert_eq!(
            successful_match_external.other_order_id, order1.id,
            "External match should find order1 (externally matchable)"
        );
    }

    #[test]
    fn test_find_match_external_no_match_when_no_externally_matchable() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();
        let input_account_id = AccountId::new_v4();
        let counterparty_account_id = AccountId::new_v4();

        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2); // 2 B per A
        let input_range = 0..=100;

        // Create a counterparty order that is NOT externally matchable
        let mut order = create_counterparty_order(500, FixedPoint::from_f64_round_down(0.4));
        order.metadata.allow_external_matches = false;
        engine.upsert_order(counterparty_account_id, &order, 500, pool.clone());

        // find_match (internal) should still match
        let result_internal = engine.find_match(
            input_account_id,
            PrivacyRing::Ring0,
            input_pair,
            input_range.clone(),
            pool.clone(),
            TimestampedPriceFp::from(price),
        );
        assert!(
            result_internal.is_some(),
            "Internal match should work regardless of externally_matchable"
        );

        // find_match_external should NOT match
        let result_external = engine.find_match_external(
            PrivacyRing::Ring0,
            input_pair,
            input_range,
            pool,
            TimestampedPriceFp::from(price),
        );
        assert!(
            result_external.is_none(),
            "External match should not find non-externally-matchable orders"
        );
    }

    // ------------------------------
    // | Range-Based Matching Tests |
    // ------------------------------

    #[test]
    fn test_find_match_with_nonzero_minimum() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();
        let input_account_id = AccountId::new_v4();
        let counterparty_account_id = AccountId::new_v4();

        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2); // 2 B per A
        let input_range = 50..=100; // Must provide at least 50 A

        // Counterparty has 500 B available
        let counterparty_order =
            create_counterparty_order(500, FixedPoint::from_f64_round_down(0.4));
        engine.upsert_order(counterparty_account_id, &counterparty_order, 500, pool.clone());

        let result = engine.find_match(
            input_account_id,
            PrivacyRing::Ring0,
            input_pair,
            input_range,
            pool,
            TimestampedPriceFp::from(price),
        );
        assert!(result.is_some());

        let successful_match = result.unwrap();
        let ob1 = successful_match.match_result.party0_obligation();

        // Should match: 100 A -> 200 B (limited by input_range max)
        assert_eq!(ob1.amount_in, 100);
        assert_eq!(ob1.amount_out, 200);
    }

    #[test]
    fn test_find_match_no_intersection_input_min_too_high() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();
        let input_account_id = AccountId::new_v4();
        let counterparty_account_id = AccountId::new_v4();

        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2); // 2 B per A
        // Input party requires at least 200 A (-> 400 B output)
        let input_range = 200..=500;

        // Counterparty only has 100 B available
        // At price 2, 100 B corresponds to 50 A input
        // Implied output range: 400..=1000 B
        // Counterparty's range: min_fill_size..=100 = 1..=100 B
        let counterparty_order =
            create_counterparty_order(100, FixedPoint::from_f64_round_down(0.4));
        engine.upsert_order(counterparty_account_id, &counterparty_order, 100, pool.clone());

        let result = engine.find_match(
            input_account_id,
            PrivacyRing::Ring0,
            input_pair,
            input_range,
            pool,
            TimestampedPriceFp::from(price),
        );
        assert!(result.is_none(), "Should not match when ranges don't intersect");
    }

    #[test]
    fn test_find_match_no_intersection_counterparty_min_fill_too_high() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();
        let input_account_id = AccountId::new_v4();
        let counterparty_account_id = AccountId::new_v4();

        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2); // 2 B per A
        // Input party can provide up to 20 A (-> 40 B output)
        let input_range = 0..=20;

        // Counterparty requires at least 100 B min_fill_size
        // Input's output range: 0..=40 B
        // Counterparty's range: 100..=500 B
        // These ranges don't intersect (40 < 100)
        let mut counterparty_order =
            create_counterparty_order(500, FixedPoint::from_f64_round_down(0.4));
        counterparty_order.metadata.min_fill_size = 100;
        engine.upsert_order(counterparty_account_id, &counterparty_order, 500, pool.clone());

        let result = engine.find_match(
            input_account_id,
            PrivacyRing::Ring0,
            input_pair,
            input_range,
            pool,
            TimestampedPriceFp::from(price),
        );
        assert!(
            result.is_none(),
            "Should not match when counterparty min_fill_size exceeds output"
        );
    }

    #[test]
    fn test_find_match_partial_range_intersection() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();
        let input_account_id = AccountId::new_v4();
        let counterparty_account_id = AccountId::new_v4();

        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2); // 2 B per A
        // Input party can provide 30-100 A (-> 60-200 B output)
        let input_range = 30..=100;

        // Counterparty has min_fill_size=50, matchable_amount=80
        // Counterparty's range: 50..=80 B
        // Input's output range: 60..=200 B
        // Intersection: 60..=80 B
        let mut counterparty_order =
            create_counterparty_order(80, FixedPoint::from_f64_round_down(0.4));
        counterparty_order.metadata.min_fill_size = 50;
        engine.upsert_order(counterparty_account_id, &counterparty_order, 80, pool.clone());

        let result = engine.find_match(
            input_account_id,
            PrivacyRing::Ring0,
            input_pair,
            input_range,
            pool,
            TimestampedPriceFp::from(price),
        );
        assert!(result.is_some(), "Should match when ranges partially intersect");

        let successful_match = result.unwrap();
        let ob1 = successful_match.match_result.party0_obligation();

        // Match amount should be min(counterparty.matchable_amount, output_range.end)
        // = min(80, 200) = 80 B
        assert_eq!(ob1.amount_out, 80);
        // 80 B / 2 = 40 A
        assert_eq!(ob1.amount_in, 40);
    }

    #[test]
    fn test_find_match_exact_boundary_intersection() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();
        let input_account_id = AccountId::new_v4();
        let counterparty_account_id = AccountId::new_v4();

        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2); // 2 B per A
        // Input party can provide 25-50 A (-> 50-100 B output)
        let input_range = 25..=50;

        // Counterparty has min_fill_size=100, matchable_amount=200
        // Counterparty's range: 100..=200 B
        // Input's output range: 50..=100 B
        // Intersection: exactly at 100 B (boundary)
        let mut counterparty_order =
            create_counterparty_order(200, FixedPoint::from_f64_round_down(0.4));
        counterparty_order.metadata.min_fill_size = 100;
        engine.upsert_order(counterparty_account_id, &counterparty_order, 200, pool.clone());

        let result = engine.find_match(
            input_account_id,
            PrivacyRing::Ring0,
            input_pair,
            input_range,
            pool,
            TimestampedPriceFp::from(price),
        );
        assert!(result.is_some(), "Should match when ranges touch at boundary");

        let successful_match = result.unwrap();
        let ob1 = successful_match.match_result.party0_obligation();

        // Match at the boundary: 100 B
        assert_eq!(ob1.amount_out, 100);
        assert_eq!(ob1.amount_in, 50);
    }

    #[test]
    fn test_find_match_skips_non_intersecting_finds_intersecting() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();
        let input_account_id = AccountId::new_v4();
        let counterparty_account_id = AccountId::new_v4();

        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2); // 2 B per A
        // Input party can provide 40-60 A (-> 80-120 B output)
        let input_range = 40..=60;

        // Order 1: Large but min_fill_size too high (doesn't intersect)
        // range: 200..=500 B, but input's output range is 80..=120
        let mut order1 = create_counterparty_order(500, FixedPoint::from_f64_round_down(0.4));
        order1.metadata.min_fill_size = 200;

        // Order 2: Smaller but intersects
        // range: 50..=100 B, intersects with 80..=120 at 80..=100
        let mut order2 = create_counterparty_order(100, FixedPoint::from_f64_round_down(0.4));
        order2.metadata.min_fill_size = 50;

        engine.upsert_order(counterparty_account_id, &order1, 500, pool.clone());
        engine.upsert_order(counterparty_account_id, &order2, 100, pool.clone());

        let result = engine.find_match(
            input_account_id,
            PrivacyRing::Ring0,
            input_pair,
            input_range,
            pool,
            TimestampedPriceFp::from(price),
        );
        assert!(result.is_some());

        // Should skip order1 (no intersection) and match with order2
        let successful_match = result.unwrap();
        assert_eq!(successful_match.other_order_id, order2.id, "Should match order2, not order1");

        let ob1 = successful_match.match_result.party0_obligation();
        // Match amount: min(100, 120) = 100 B
        assert_eq!(ob1.amount_out, 100);
        assert_eq!(ob1.amount_in, 50);
    }

    #[test]
    fn test_find_match_range_with_fractional_price() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();
        let input_account_id = AccountId::new_v4();
        let counterparty_account_id = AccountId::new_v4();

        let input_pair = test_pair();
        let price = FixedPoint::from_f64_round_down(1.5); // 1.5 B per A
        // Input party can provide 40-80 A (-> 60-120 B output at price 1.5)
        let input_range = 40..=80;

        // Counterparty has min_fill_size=50, matchable_amount=100
        // Counterparty's range: 50..=100 B
        // Input's output range: 60..=120 B
        // Intersection: 60..=100 B
        let mut counterparty_order =
            create_counterparty_order(100, FixedPoint::from_f64_round_down(0.5));
        counterparty_order.metadata.min_fill_size = 50;
        engine.upsert_order(counterparty_account_id, &counterparty_order, 100, pool.clone());

        let result = engine.find_match(
            input_account_id,
            PrivacyRing::Ring0,
            input_pair,
            input_range,
            pool,
            TimestampedPriceFp::from(price),
        );
        assert!(result.is_some(), "Should match with fractional price");

        let successful_match = result.unwrap();
        let ob1 = successful_match.match_result.party0_obligation();

        // Match amount: min(counterparty.matchable_amount, output_range.end)
        // = min(100, 120) = 100 B
        assert_eq!(ob1.amount_out, 100);
        // input_amount = 100 / 1.5 = 66.67, but due to floor rounding ≈ 66
        assert_eq!(ob1.amount_in, 66);
    }

    // -------------------------------------
    // | All Pools External Matching Tests |
    // -------------------------------------

    #[test]
    fn test_find_match_external_all_pools_finds_orders_across_pools() {
        let engine = MatchingEngine::new();
        let pool1 = "pool1".to_string();
        let pool2 = "pool2".to_string();
        let counterparty_account_id = AccountId::new_v4();

        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2); // 2 B per A
        let input_range = 0..=100;

        // Add an externally matchable order to pool1
        let mut order1 = create_counterparty_order(300, FixedPoint::from_f64_round_down(0.4));
        order1.metadata.allow_external_matches = true;
        engine.upsert_order(counterparty_account_id, &order1, 300, pool1.clone());

        // Add an externally matchable order to pool2
        let mut order2 = create_counterparty_order(200, FixedPoint::from_f64_round_down(0.4));
        order2.metadata.allow_external_matches = true;
        engine.upsert_order(counterparty_account_id, &order2, 200, pool2.clone());

        // All-pools external match should find the largest order (order1 from pool1)
        let result = engine.find_match_external_all_pools(
            PrivacyRing::Ring0,
            input_pair,
            input_range,
            TimestampedPriceFp::from(price),
        );
        assert!(result.is_some(), "Should find a match across all pools");

        let successful_match = result.unwrap();
        assert_eq!(
            successful_match.other_order_id, order1.id,
            "Should match with the largest order across pools"
        );
    }

    #[test]
    fn test_find_match_external_all_pools_selects_largest_order() {
        let engine = MatchingEngine::new();
        let pool1 = "pool1".to_string();
        let pool2 = "pool2".to_string();
        let pool3 = "pool3".to_string();
        let counterparty_account_id = AccountId::new_v4();

        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2);
        let input_range = 0..=1000;

        // Add orders to different pools with varying sizes
        let mut order1 = create_counterparty_order(100, FixedPoint::from_f64_round_down(0.4));
        order1.metadata.allow_external_matches = true;
        engine.upsert_order(counterparty_account_id, &order1, 100, pool1.clone());

        let mut order2 = create_counterparty_order(500, FixedPoint::from_f64_round_down(0.4));
        order2.metadata.allow_external_matches = true;
        engine.upsert_order(counterparty_account_id, &order2, 500, pool2.clone());

        let mut order3 = create_counterparty_order(300, FixedPoint::from_f64_round_down(0.4));
        order3.metadata.allow_external_matches = true;
        engine.upsert_order(counterparty_account_id, &order3, 300, pool3.clone());

        // All-pools match should select order2 (largest at 500)
        let result = engine.find_match_external_all_pools(
            PrivacyRing::Ring0,
            input_pair,
            input_range,
            TimestampedPriceFp::from(price),
        );
        assert!(result.is_some());

        let successful_match = result.unwrap();
        assert_eq!(
            successful_match.other_order_id, order2.id,
            "Should select the largest order across all pools"
        );

        // Verify match amount
        let ob1 = successful_match.match_result.party0_obligation();
        assert_eq!(ob1.amount_out, 500);
        assert_eq!(ob1.amount_in, 250);
    }

    #[test]
    fn test_find_match_external_all_pools_only_matches_externally_matchable() {
        let engine = MatchingEngine::new();
        let pool1 = "pool1".to_string();
        let pool2 = "pool2".to_string();
        let counterparty_account_id = AccountId::new_v4();

        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2);
        let input_range = 0..=1000;

        // Add a large order that is NOT externally matchable
        let mut order1 = create_counterparty_order(1000, FixedPoint::from_f64_round_down(0.4));
        order1.metadata.allow_external_matches = false;
        engine.upsert_order(counterparty_account_id, &order1, 1000, pool1.clone());

        // Add a smaller order that IS externally matchable
        let mut order2 = create_counterparty_order(200, FixedPoint::from_f64_round_down(0.4));
        order2.metadata.allow_external_matches = true;
        engine.upsert_order(counterparty_account_id, &order2, 200, pool2.clone());

        // All-pools external match should only find order2 (externally matchable)
        let result = engine.find_match_external_all_pools(
            PrivacyRing::Ring0,
            input_pair,
            input_range,
            TimestampedPriceFp::from(price),
        );
        assert!(result.is_some());

        let successful_match = result.unwrap();
        assert_eq!(
            successful_match.other_order_id, order2.id,
            "Should only match externally matchable orders"
        );
    }

    #[test]
    fn test_find_match_external_all_pools_no_match_when_none_externally_matchable() {
        let engine = MatchingEngine::new();
        let pool1 = "pool1".to_string();
        let pool2 = "pool2".to_string();
        let counterparty_account_id = AccountId::new_v4();

        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2);
        let input_range = 0..=100;

        // Add orders that are NOT externally matchable
        let mut order1 = create_counterparty_order(500, FixedPoint::from_f64_round_down(0.4));
        order1.metadata.allow_external_matches = false;
        engine.upsert_order(counterparty_account_id, &order1, 500, pool1.clone());

        let mut order2 = create_counterparty_order(300, FixedPoint::from_f64_round_down(0.4));
        order2.metadata.allow_external_matches = false;
        engine.upsert_order(counterparty_account_id, &order2, 300, pool2.clone());

        // All-pools external match should find nothing
        let result = engine.find_match_external_all_pools(
            PrivacyRing::Ring0,
            input_pair,
            input_range,
            TimestampedPriceFp::from(price),
        );
        assert!(result.is_none(), "Should not match when no orders are externally matchable");
    }
}
