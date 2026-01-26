//! A book of orders
//!
//! Each pair has a book, sorted by decreasing matchable amount

use std::collections::BTreeSet;
use std::{cmp::Ordering, ops::RangeInclusive};

use circuit_types::{Amount, fixed_point::FixedPoint};
use rustc_hash::FxHashMap;
use types_account::{OrderId, order::Order};
use types_core::AccountId;

/// A key for sorting orders by descending matchable amount
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReverseAmountKey {
    /// The matchable amount
    amount: Amount,
    /// The order id
    order_id: OrderId,
}

impl ReverseAmountKey {
    /// Create a new reverse amount key
    pub(crate) fn new(amount: Amount, order_id: OrderId) -> Self {
        Self { amount, order_id }
    }
}

impl PartialOrd for ReverseAmountKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ReverseAmountKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare by amount descending, then by order_id ascending for tie-breaking
        match other.amount.cmp(&self.amount) {
            Ordering::Equal => self.order_id.cmp(&other.order_id),
            other => other,
        }
    }
}

/// A book of orders
pub struct Book {
    /// A map of order id to matchable amount
    ///
    /// Used to construct the key for the sorted amounts map
    order_map: FxHashMap<OrderId, BookOrder>,
    /// A btree-sorted list of matchable amounts to order id pairs
    ///
    /// We use this to iterate through the book in the order of the
    sorted_amounts: BTreeSet<ReverseAmountKey>,
}

/// The details of an order on the book
pub(crate) struct BookOrder {
    /// The account ID that owns this order
    pub account_id: AccountId,
    /// The matchable amount of the order
    ///
    /// This may be smaller than the original order's amount if the order's is
    /// undercapitalized by the balances in the account
    pub matchable_amount: Amount,
    /// The minimum price of the order
    ///
    /// In units of output_token / input_token
    pub min_price: FixedPoint,
    /// The minimum fill size of the order
    pub min_fill_size: Amount,
    /// Whether this order is externally matchable
    pub externally_matchable: bool,
}

impl BookOrder {
    /// Create a new book order from a given order and matchable amount
    pub(crate) fn new(account_id: AccountId, order: &Order, matchable_amount: Amount) -> Self {
        Self {
            account_id,
            matchable_amount,
            min_price: order.min_price(),
            min_fill_size: order.min_fill_size(),
            externally_matchable: order.allow_external_matches(),
        }
    }
}

impl Book {
    /// Create a new book
    pub fn new() -> Self {
        Self { order_map: FxHashMap::default(), sorted_amounts: BTreeSet::new() }
    }

    // --- Getters --- //

    /// Whether the book contains an order
    pub fn contains_order(&self, order_id: OrderId) -> bool {
        self.order_map.contains_key(&order_id)
    }

    /// Get the matchable amount for an order
    pub fn get_matchable_amount(&self, order_id: OrderId) -> Option<Amount> {
        self.order_map.get(&order_id).map(|order| order.matchable_amount)
    }

    // --- Setters --- //

    /// Add an order to the book
    pub fn add_order(&mut self, account_id: AccountId, order: &Order, matchable_amount: Amount) {
        let book_order = BookOrder::new(account_id, order, matchable_amount);
        self.order_map.insert(order.id, book_order);
        self.sorted_amounts.insert(ReverseAmountKey::new(matchable_amount, order.id));
    }

    /// Remove an order from the book
    pub fn remove_order(&mut self, order_id: OrderId) {
        if let Some(order) = self.order_map.remove(&order_id) {
            let key = ReverseAmountKey::new(order.matchable_amount, order_id);
            self.sorted_amounts.remove(&key);
        }
    }

    /// Update the matchable amount for an order
    pub fn update_order(&mut self, account_id: AccountId, order: &Order, matchable_amount: Amount) {
        // Delete the old entry and re-insert the new one
        self.remove_order(order.id);
        self.add_order(account_id, order, matchable_amount);
    }

    // --- Matching --- //

    /// Find a match for a given order
    ///
    /// Orders belonging to `exclude_account_id` will be skipped to prevent
    /// self-matches.
    ///
    /// If `require_externally_matchable` is `true`, only matches against
    /// orders that have `externally_matchable` set to `true`. If `false`, does
    /// not filter on externally matchable status.
    ///
    /// Returns the order id, the match amount, and the matchable amount bounds
    /// (min and max) of the counterparty.
    pub fn find_match(
        &self,
        exclude_account_id: AccountId,
        price: FixedPoint,
        amount_range: RangeInclusive<Amount>,
        require_externally_matchable: bool,
    ) -> Option<(OrderId, Amount, RangeInclusive<Amount>)> {
        // Build an iterator over orders sorted by descending matchable amount
        let orders = self.iter();
        for (oid, order) in orders {
            // Skip orders from the same account (prevent self-matches)
            if exclude_account_id == order.account_id {
                continue;
            }

            // Skip orders whose validation conditions are not met
            let order_range = order.min_fill_size..=order.matchable_amount;
            let ranges_intersect = ranges_intersect(&order_range, &amount_range);
            if order.min_price > price || !ranges_intersect {
                continue;
            }

            // Filter on externally matchable if required
            if require_externally_matchable && !order.externally_matchable {
                continue;
            }

            // Compute the match amount
            let match_amount = Amount::min(order.matchable_amount, *amount_range.end());
            let matchable_amount_bounds = order.min_fill_size..=order.matchable_amount;
            return Some((*oid, match_amount, matchable_amount_bounds));
        }

        None
    }
}

// --- Iteration --- //

impl Book {
    /// Iterate through the book in the order of the sorted amounts
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&OrderId, &BookOrder)> {
        self.sorted_amounts
            .iter()
            .map(|key| (&key.order_id, self.order_map.get(&key.order_id).unwrap()))
    }
}

// -----------
// | Helpers |
// -----------

/// Whether two ranges intersect
#[inline]
fn ranges_intersect(range1: &RangeInclusive<Amount>, range2: &RangeInclusive<Amount>) -> bool {
    let intersect_min = Amount::max(*range1.start(), *range2.start());
    let intersect_max = Amount::min(*range1.end(), *range2.end());
    intersect_min <= intersect_max
}

#[cfg(test)]
mod tests {
    use super::*;
    use types_account::{account::order::Order, order::mocks::mock_order};

    // -----------
    // | Helpers |
    // -----------

    /// Create a test order with the given matchable amount
    fn create_test_order(matchable_amount: Amount) -> Order {
        let mut order = mock_order();
        order.intent.inner.amount_in = matchable_amount * 2;
        order.intent.inner.min_price = FixedPoint::from_integer(1);
        order
    }

    #[test]
    fn test_add_order() {
        let mut book = Book::new();
        let order = create_test_order(100);
        let account_id = AccountId::new_v4();

        assert!(!book.contains_order(order.id));
        book.add_order(account_id, &order, 100);
        assert!(book.contains_order(order.id));
    }

    #[test]
    fn test_get_matchable_amount() {
        let mut book = Book::new();
        let order = create_test_order(150);
        let account_id = AccountId::new_v4();

        assert_eq!(book.get_matchable_amount(order.id), None);
        book.add_order(account_id, &order, 150);
        assert_eq!(book.get_matchable_amount(order.id), Some(150));
    }

    #[test]
    fn test_update_order() {
        let mut book = Book::new();
        let order = create_test_order(100);
        let account_id = AccountId::new_v4();

        book.add_order(account_id, &order, 100);
        assert_eq!(book.get_matchable_amount(order.id), Some(100));

        book.update_order(account_id, &order, 200);
        assert_eq!(book.get_matchable_amount(order.id), Some(200));
    }

    #[test]
    fn test_remove_order() {
        let mut book = Book::new();
        let order = create_test_order(100);
        let account_id = AccountId::new_v4();

        book.add_order(account_id, &order, 100);
        assert!(book.contains_order(order.id));

        book.remove_order(order.id);
        assert!(!book.contains_order(order.id));
        assert_eq!(book.get_matchable_amount(order.id), None);
    }

    #[test]
    fn test_remove_nonexistent_order() {
        let mut book = Book::new();
        let order = create_test_order(100);

        // Should not panic
        book.remove_order(order.id);
        assert!(!book.contains_order(order.id));
    }

    // -------------------
    // | Iteration Tests |
    // -------------------

    #[test]
    fn test_iteration_order_descending() {
        let mut book = Book::new();
        let account_id = AccountId::new_v4();

        // Add orders in random order
        let order1 = create_test_order(300);
        let order2 = create_test_order(100);
        let order3 = create_test_order(200);

        book.add_order(account_id, &order1, 300);
        book.add_order(account_id, &order2, 100);
        book.add_order(account_id, &order3, 200);

        // Iteration should be in descending order (largest to smallest)
        let amounts: Vec<OrderId> = book.iter().map(|(id, _)| *id).collect();
        assert_eq!(amounts, vec![order1.id, order3.id, order2.id]);
    }

    #[test]
    fn test_iteration_order_after_update() {
        let mut book = Book::new();
        let account_id = AccountId::new_v4();

        let order1 = create_test_order(100);
        let order2 = create_test_order(200);
        let order3 = create_test_order(300);

        book.add_order(account_id, &order1, 100);
        book.add_order(account_id, &order2, 200);
        book.add_order(account_id, &order3, 300);

        // Verify initial order (descending)
        let order_ids: Vec<OrderId> = book.iter().map(|(id, _)| *id).collect();
        assert_eq!(order_ids, vec![order3.id, order2.id, order1.id]);

        // Update order2 to have the largest amount
        book.update_order(account_id, &order2, 400);

        // Verify order is maintained after update (descending)
        let order_ids: Vec<OrderId> = book.iter().map(|(id, _)| *id).collect();
        assert_eq!(order_ids, vec![order2.id, order3.id, order1.id]);
    }

    #[test]
    fn test_iteration_order_after_multiple_updates() {
        let mut book = Book::new();
        let account_id = AccountId::new_v4();

        let order1 = create_test_order(100);
        let order2 = create_test_order(200);
        let order3 = create_test_order(300);

        book.add_order(account_id, &order1, 100);
        book.add_order(account_id, &order2, 200);
        book.add_order(account_id, &order3, 300);

        // Update order1 to be largest
        book.update_order(account_id, &order1, 500);
        let order_ids: Vec<OrderId> = book.iter().map(|(id, _)| *id).collect();
        assert_eq!(order_ids, vec![order1.id, order3.id, order2.id]);

        // Update order3 to be smallest
        book.update_order(account_id, &order3, 50);
        let order_ids: Vec<OrderId> = book.iter().map(|(id, _)| *id).collect();
        assert_eq!(order_ids, vec![order1.id, order2.id, order3.id]);

        // Update order2 to be middle
        book.update_order(account_id, &order2, 250);
        let order_ids: Vec<OrderId> = book.iter().map(|(id, _)| *id).collect();
        assert_eq!(order_ids, vec![order1.id, order2.id, order3.id]);
    }

    #[test]
    fn test_iteration_order_with_duplicate_amounts() {
        let mut book = Book::new();
        let account_id = AccountId::new_v4();

        let order1 = create_test_order(100);
        let order2 = create_test_order(100);
        let order3 = create_test_order(100);

        book.add_order(account_id, &order1, 100);
        book.add_order(account_id, &order2, 100);
        book.add_order(account_id, &order3, 100);

        // All orders should be present, sorted by OrderId when amounts are equal
        let order_ids: Vec<OrderId> = book.iter().map(|(id, _)| *id).collect();
        // When amounts are equal, orders are sorted by OrderId (ascending)
        let mut expected_ids = vec![order1.id, order2.id, order3.id];
        expected_ids.sort();
        assert_eq!(order_ids, expected_ids);

        // All should have the same matchable amount
        for (_, order) in book.iter() {
            assert_eq!(order.matchable_amount, 100);
        }
    }

    #[test]
    fn test_iteration_order_after_remove() {
        let mut book = Book::new();
        let account_id = AccountId::new_v4();

        let order1 = create_test_order(100);
        let order2 = create_test_order(200);
        let order3 = create_test_order(300);

        book.add_order(account_id, &order1, 100);
        book.add_order(account_id, &order2, 200);
        book.add_order(account_id, &order3, 300);

        // Remove middle order
        book.remove_order(order2.id);

        let order_ids: Vec<OrderId> = book.iter().map(|(id, _)| *id).collect();
        assert_eq!(order_ids, vec![order3.id, order1.id]);
    }

    #[test]
    fn test_iteration_empty_book() {
        let book = Book::new();

        let count: usize = book.iter().count();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_iteration_single_order() {
        let mut book = Book::new();
        let order = create_test_order(100);
        let account_id = AccountId::new_v4();

        book.add_order(account_id, &order, 100);

        let order_ids: Vec<OrderId> = book.iter().map(|(id, _)| *id).collect();
        assert_eq!(order_ids, vec![order.id]);
    }

    // -------------------------------
    // | Self-Match Prevention Tests |
    // -------------------------------

    #[test]
    fn test_find_match_skips_same_account() {
        let mut book = Book::new();
        let same_account = AccountId::new_v4();

        // Add an order from the same account
        let order1 = create_test_order(200);
        book.add_order(same_account, &order1, 200);

        // Try to find a match excluding the same account
        let price = FixedPoint::from_integer(1);
        let amount_range = 0..=100;
        let result = book.find_match(same_account, price, amount_range, false);

        // Should not find a match (self-match prevention)
        assert!(result.is_none(), "Should not match orders from the same account");
    }

    #[test]
    fn test_find_match_skips_same_account_finds_different() {
        let mut book = Book::new();
        let account_a = AccountId::new_v4();
        let account_b = AccountId::new_v4();

        // Add a larger order from account A (same account as requester)
        let order1 = create_test_order(300);
        book.add_order(account_a, &order1, 300);

        // Add a smaller order from account B (different account)
        let order2 = create_test_order(100);
        book.add_order(account_b, &order2, 100);

        // Try to find a match as account A
        let price = FixedPoint::from_integer(1);
        let amount_range = 0..=50;
        let result = book.find_match(account_a, price, amount_range, false);

        // Should skip order1 (same account) and match with order2
        assert!(result.is_some());
        let (matched_id, _, _) = result.unwrap();
        assert_eq!(matched_id, order2.id, "Should match order from different account");
    }
}
