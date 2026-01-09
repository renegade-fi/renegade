//! The matching engine

use std::sync::Arc;

use circuit_types::{Amount, fixed_point::FixedPoint};
use crypto::fields::scalar_to_u128;
use darkpool_types::settlement_obligation::{MatchResult, SettlementObligation};
use dashmap::DashMap;
use types_account::{MatchingPoolName, OrderId, order::Order, pair::Pair};

use crate::book::Book;

/// The matching engine
#[derive(Clone)]
pub struct MatchingEngine {
    /// A mapping from asset pair and matching pool to the book
    book_map: Arc<DashMap<(Pair, MatchingPoolName), Book>>,
}

impl MatchingEngine {
    /// Create a new matching engine
    pub fn new() -> Self {
        Self { book_map: Arc::new(DashMap::new()) }
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

    /// Add an order to the matching engine
    pub fn add_order(
        &self,
        order: &Order,
        matchable_amount: Amount,
        matching_pool: MatchingPoolName,
    ) {
        let pair = order.pair();
        let mut book = self.book_map.entry((pair, matching_pool)).or_insert_with(Book::new);

        book.add_order(order, matchable_amount);
    }

    /// Remove an order from the matching engine
    pub fn cancel_order(&self, order: &Order, matching_pool: MatchingPoolName) {
        let pair = order.pair();
        if let Some(mut book) = self.book_map.get_mut(&(pair, matching_pool)) {
            book.remove_order(order.id);
        }
    }

    /// Update the matchable amount for an order
    pub fn update_order(
        &self,
        order: &Order,
        matchable_amount: Amount,
        matching_pool: MatchingPoolName,
    ) {
        let pair = order.pair();
        if let Some(mut book) = self.book_map.get_mut(&(pair, matching_pool)) {
            book.update_order(order, matchable_amount);
        }
    }

    // --- Matching Operations --- //

    /// Find a match for an order
    ///
    /// The price here is specified in terms of the input order's output token /
    /// input token. I.e. it is in the same units as the input order's min
    /// price.
    ///
    /// In what follows, the input party is the party whose order is input to
    /// this method and the counterparty is the party whose order is discovered
    /// by walking the book.
    pub fn find_match(
        &self,
        input_pair: Pair,
        max_input: Amount,
        matching_pool: MatchingPoolName,
        price: FixedPoint,
    ) -> Option<(OrderId, MatchResult)> {
        let counterparty_pair = input_pair.reverse(); // Reverse the pair to get the counterparty's book
        let counterparty_price = price.inverse()?;
        let max_output = scalar_to_u128(&price.floor_mul_int(max_input));

        let book = self.book_map.get(&(counterparty_pair, matching_pool))?;
        let (counterparty_oid, counterparty_input_amount) =
            book.find_match(counterparty_price, max_output)?;
        drop(book); // Release the borrow

        // Build the match result
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
        Some((counterparty_oid, match_result))
    }
}

impl Default for MatchingEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;
    use types_account::{account::order::Order, order::mocks::mock_order_with_pair};

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
        order.intent.amount_in = matchable_amount * 2;
        order.intent.min_price = min_price;
        order.metadata.min_fill_size = 1;
        order
    }

    /// Create a counterparty order (reversed pair) with the given matchable
    /// amount and min price
    fn create_counterparty_order(matchable_amount: Amount, min_price: FixedPoint) -> Order {
        let pair = test_pair();
        let mut order = mock_order_with_pair(pair.reverse());
        order.intent.amount_in = matchable_amount * 2;
        order.intent.min_price = min_price;
        order.metadata.min_fill_size = 1;
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

        engine.add_order(&order, 100, pool.clone());
        assert!(engine.contains_order(&order, pool.clone()));
    }

    #[test]
    fn test_cancel_order() {
        let engine = MatchingEngine::new();
        let order = create_test_order(100, FixedPoint::from_integer(1));
        let pool = test_matching_pool();

        engine.add_order(&order, 100, pool.clone());
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

        // Should not panic
        engine.update_order(&order, 200, pool);
    }

    // ------------------
    // | Matching Tests |
    // ------------------

    #[test]
    fn test_find_match_basic() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();

        // Input order wants to trade token A -> token B
        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2); // 2 B per A
        let max_input = 100; // Can provide up to 100 A

        // Counterparty order wants to trade token B -> token A
        // Their min_price is in units of A/B = 1/2 = 0.5
        let counterparty_order =
            create_counterparty_order(500, FixedPoint::from_f64_round_down(0.5));
        engine.add_order(&counterparty_order, 500, pool.clone());

        let result = engine.find_match(input_pair, max_input, pool, price);
        assert!(result.is_some(), "Should find a match");

        let (matched_oid, match_result) = result.unwrap();
        assert_eq!(matched_oid, counterparty_order.id);

        let ob1 = match_result.party0_obligation();
        let ob2 = match_result.party1_obligation();

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

        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2);
        let max_input = 100;

        let result = engine.find_match(input_pair, max_input, pool, price);
        assert!(result.is_none(), "Should not find match when no counterparty orders exist");
    }

    #[test]
    fn test_find_match_price_too_low() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();

        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2); // 2 B per A
        let max_input = 100;

        // Counterparty wants at least 0.6 A per B (min_price = 0.6)
        // But at price 2.0, counterparty gets 0.5 A per B (inverse = 0.5)
        // So 0.5 < 0.6, match should fail
        let counterparty_order =
            create_counterparty_order(500, FixedPoint::from_f64_round_down(0.6));
        engine.add_order(&counterparty_order, 500, pool.clone());

        let result = engine.find_match(input_pair, max_input, pool, price);
        assert!(result.is_none(), "Should not match when price is below counterparty's min");
    }

    #[test]
    fn test_find_match_limited_by_max_input() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();

        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2); // 2 B per A
        let max_input = 50; // Limited to 50 A

        let counterparty_order =
            create_counterparty_order(500, FixedPoint::from_f64_round_down(0.4));
        engine.add_order(&counterparty_order, 500, pool.clone());

        let result = engine.find_match(input_pair, max_input, pool, price);
        assert!(result.is_some());

        let (_, match_result) = result.unwrap();
        let ob1 = match_result.party0_obligation();

        // Should be limited by max_input: 50 A -> 100 B
        assert_eq!(ob1.amount_in, 50);
        assert_eq!(ob1.amount_out, 100);
    }

    #[test]
    fn test_find_match_limited_by_counterparty_amount() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();

        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2); // 2 B per A
        let max_input = 1000; // Can provide up to 1000 A

        // Counterparty only has 100 B available
        let counterparty_order =
            create_counterparty_order(100, FixedPoint::from_f64_round_down(0.4));
        engine.add_order(&counterparty_order, 100, pool.clone());

        let result = engine.find_match(input_pair, max_input, pool, price);
        assert!(result.is_some());

        let (_, match_result) = result.unwrap();
        let ob1 = match_result.party0_obligation();

        // Should be limited by counterparty's amount: 50 A -> 100 B
        assert_eq!(ob1.amount_in, 50);
        assert_eq!(ob1.amount_out, 100);
    }

    #[test]
    fn test_find_match_multiple_orders_selects_largest() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();

        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2);
        let max_input = 1000;

        // Add multiple counterparty orders with different matchable amounts
        let order1 = create_counterparty_order(100, FixedPoint::from_f64_round_down(0.4));
        let order2 = create_counterparty_order(500, FixedPoint::from_f64_round_down(0.4));
        let order3 = create_counterparty_order(200, FixedPoint::from_f64_round_down(0.4));

        engine.add_order(&order1, 100, pool.clone());
        engine.add_order(&order2, 500, pool.clone());
        engine.add_order(&order3, 200, pool.clone());

        let result = engine.find_match(input_pair, max_input, pool, price);
        assert!(result.is_some());

        // Should match with order2 (largest matchable amount = 500)
        let (matched_oid, match_result) = result.unwrap();
        assert_eq!(matched_oid, order2.id);

        // Should match 250 A -> 500 B (limited by counterparty's 500 B)
        let ob1 = match_result.party0_obligation();
        assert_eq!(ob1.amount_in, 250);
        assert_eq!(ob1.amount_out, 500);
    }

    #[test]
    fn test_find_match_different_matching_pools() {
        let engine = MatchingEngine::new();
        let pool1 = "pool1".to_string();
        let pool2 = "pool2".to_string();

        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2);
        let max_input = 100;

        // Add order to pool1
        let order1 = create_counterparty_order(500, FixedPoint::from_f64_round_down(0.4));
        engine.add_order(&order1, 500, pool1.clone());

        // Should find match in pool1
        let result1 = engine.find_match(input_pair, max_input, pool1.clone(), price);
        assert!(result1.is_some());
        let (oid, _) = result1.unwrap();
        assert_eq!(oid, order1.id);

        // Should not find match in pool2
        let result2 = engine.find_match(input_pair, max_input, pool2, price);
        assert!(result2.is_none());
    }

    #[test]
    fn test_find_match_min_fill_size_constraint() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();

        let input_pair = test_pair();
        let price = FixedPoint::from_integer(2);
        let max_input = 10; // Small amount

        // Counterparty has large min_fill_size
        let mut counterparty_order =
            create_counterparty_order(500, FixedPoint::from_f64_round_down(0.4));
        counterparty_order.metadata.min_fill_size = 100; // Requires at least 100 B
        engine.add_order(&counterparty_order, 500, pool.clone());

        // max_input of 10 A -> 20 B, but counterparty needs at least 100 B
        let result = engine.find_match(input_pair, max_input, pool, price);
        assert!(result.is_none(), "Should not match when min_fill_size not met");
    }

    #[test]
    fn test_find_match_fractional_price() {
        let engine = MatchingEngine::new();
        let pool = test_matching_pool();

        let input_pair = test_pair();
        let price = FixedPoint::from_f64_round_down(1.5); // 1.5 B per A
        let max_input = 100;

        let counterparty_order =
            create_counterparty_order(500, FixedPoint::from_f64_round_down(0.5));
        engine.add_order(&counterparty_order, 500, pool.clone());

        let result = engine.find_match(input_pair, max_input, pool, price);
        assert!(result.is_some());

        let (_, match_result) = result.unwrap();
        let ob1 = match_result.party0_obligation();

        // 100 A * 1.5 = 150 B
        // Due to floor rounding in fixed-point arithmetic, input amount is rounded down
        assert_eq!(ob1.amount_in, 99);
        assert_eq!(ob1.amount_out, 150);
    }
}
