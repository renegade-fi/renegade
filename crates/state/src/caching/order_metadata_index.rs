//! Indexing of orders by metadata
//!
//! Specifically, we build an efficiently queryable mapping from pair -> side ->
//! (matchable_amount, order_id)
//!
//! This allows the matching engine to efficiently query a narrow set of
//! candidate orders to match against a target order.

use circuit_types::Amount;
use dashmap::DashMap;
use types_account::{
    account::{OrderId, pair::Pair},
    order::Order,
};

/// The order metadata index
#[derive(Default)]
pub struct OrderMetadataIndex {
    /// The mapping from pair -> (matchable_amount, order_id)
    index: DashMap<Pair, SortedVec<(Amount, OrderId)>>,
    /// A reverse mapping from order_id to pair
    ///
    /// This is used to efficiently query the index by order_id for updates and
    /// deletion
    reverse_index: DashMap<OrderId, Pair>,
}

impl OrderMetadataIndex {
    /// Construct a new order metadata index
    pub fn new() -> Self {
        let index = DashMap::new();
        let reverse_index = DashMap::new();
        Self { index, reverse_index }
    }

    // --- Getters --- //

    /// Get all orders for a given pair and side, sorted by matchable amount
    pub fn get_orders(&self, pair: &Pair) -> Vec<OrderId> {
        match self.index.get(pair) {
            Some(v) => v.iter().map(|(_, iid)| *iid).collect(),
            None => Vec::new(),
        }
    }

    /// Get all orders in the index
    ///
    /// No sort ordering is guaranteed, given that the units on which individual
    /// orders are sorted may differ
    pub fn get_all_orders(&self) -> Vec<OrderId> {
        self.reverse_index.iter().map(|entry| *entry.key()).collect()
    }

    /// Get the pair and side for a given order_id
    pub fn get_pair(&self, order_id: &OrderId) -> Option<Pair> {
        self.reverse_index.get(order_id).map(|entry| *entry.value())
    }

    /// Returns whether an order exists in the index synchronously
    pub fn order_exists(&self, order_id: &OrderId) -> bool {
        self.reverse_index.contains_key(order_id)
    }

    // --- Setters --- //

    /// Add an order to the index
    pub fn add_order(&self, order_id: OrderId, order: &Order, matchable_amount: Amount) {
        let pair = order.pair();
        let mut entry = self.index.entry(pair).or_insert_with(SortedVec::new);
        entry.insert((matchable_amount, order_id));

        // Update the reverse index
        self.reverse_index.insert(order_id, pair);
    }

    /// Update the matchable amount for an order
    ///
    /// Returns the old matchable amount if it was updated, otherwise None
    pub fn update_matchable_amount(
        &self,
        order_id: OrderId,
        matchable_amount: Amount,
    ) -> Option<Amount> {
        let pair = self.get_pair(&order_id).unwrap();
        let mut entry = self.index.entry(pair).or_insert_with(SortedVec::new);

        // Remove the old entry
        let old_amount = if let Some(idx) = entry.find_index(|(_, oid)| *oid == order_id) {
            let (amt, _) = entry.remove(idx);
            Some(amt)
        } else {
            None
        };

        // Insert the new entry (this will maintain the sort order)
        entry.insert((matchable_amount, order_id));
        old_amount
    }

    /// Remove an order from the index
    ///
    /// Note that we do not clean up sub-index entries when their
    /// lists become empty.
    ///
    /// Returns the pair, side, and matchable amount if the order was removed,
    /// otherwise None
    pub fn remove_order(&self, order_id: &OrderId) -> Option<(Pair, Amount)> {
        // Get the pair and side from the reverse index
        let pair = self.get_pair(order_id)?;

        // Remove from the main index
        let mut entry = self.index.get_mut(&pair)?;
        let old_amount = if let Some(idx) = entry.find_index(|(_, oid)| oid == order_id) {
            let (amt, _) = entry.remove(idx);
            Some(amt)
        } else {
            None
        };

        // Remove from the reverse index
        self.reverse_index.remove(order_id);
        old_amount.map(|amt| (pair, amt))
    }
}

/// A vector that is kept sorted on insert
struct SortedVec<T> {
    /// The inner vector
    vec: Vec<T>,
}

impl<T: Ord> SortedVec<T> {
    /// Construct a new sorted vector
    pub fn new() -> Self {
        Self { vec: Vec::new() }
    }

    // --- Getters --- //

    /// Get the element at index i
    #[cfg(test)]
    pub fn get(&self, i: usize) -> Option<&T> {
        self.vec.get(i)
    }

    /// Find the index of an element in the vector using the given filter method
    pub fn find_index(&self, filter: impl Fn(&T) -> bool) -> Option<usize> {
        self.vec.iter().position(filter)
    }

    /// Get the vector
    #[cfg(test)]
    pub fn vec(&self) -> &Vec<T> {
        &self.vec
    }

    /// Iterate over the vector
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.vec.iter()
    }

    // --- Setters --- //

    /// Insert an element into the vector
    pub fn insert(&mut self, element: T) {
        // For descending order, we want to insert after all elements that are greater
        // than or equal to the current element
        // The `binary_search_by` returns the index at which the element can be found,
        // or an `Err` containing the index at which the element should be inserted
        let index = match self.vec.binary_search_by(|probe| element.cmp(probe)) {
            Ok(i) => i,
            Err(i) => i,
        };
        self.vec.insert(index, element);
    }

    /// Remove an element from the vector
    pub fn remove(&mut self, index: usize) -> T {
        self.vec.remove(index)
    }
}

#[cfg(test)]
mod sorted_vec_tests {
    use super::*;
    use rand::{Rng, seq::SliceRandom, thread_rng};

    #[test]
    fn test_sorted_vec_empty() {
        let vec: SortedVec<i32> = SortedVec::new();
        assert!(vec.vec().is_empty());
    }

    #[test]
    fn test_sorted_vec_basic() {
        let mut vec = SortedVec::new();
        vec.insert(3);
        vec.insert(1);
        vec.insert(4);
        vec.insert(2);

        assert_eq!(vec.vec(), &[4, 3, 2, 1]);
    }

    #[test]
    fn test_sorted_vec_duplicates() {
        let mut vec = SortedVec::new();
        vec.insert(2);
        vec.insert(2);
        vec.insert(2);
        vec.insert(1);
        vec.insert(1);

        assert_eq!(vec.vec(), &[2, 2, 2, 1, 1]);
    }

    #[test]
    fn test_sorted_vec_single_element() {
        let mut vec = SortedVec::new();
        vec.insert(1);
        assert_eq!(vec.vec(), &[1]);
    }

    #[test]
    fn test_sorted_vec_fuzz() {
        // Create a vector of 100 random numbers
        let mut rng = thread_rng();
        let mut numbers: Vec<i32> = (0..100).map(|_| rng.gen_range(-1000..1000)).collect();

        // Insert them into SortedVec
        let mut sorted_vec = SortedVec::new();
        for &n in &numbers {
            sorted_vec.insert(n);
        }

        // Sort the original vector in descending order for comparison
        numbers.sort();
        numbers.reverse();
        assert_eq!(sorted_vec.vec(), &numbers);
    }

    #[test]
    fn test_sorted_vec_random_order() {
        let mut vec = SortedVec::new();
        let mut numbers: Vec<i32> = (1..=10).collect();
        numbers.shuffle(&mut thread_rng());

        // Insert in random order
        for n in numbers {
            vec.insert(n);
        }

        // Should be sorted in descending order
        assert_eq!(vec.vec(), &[10, 9, 8, 7, 6, 5, 4, 3, 2, 1]);
    }
}

#[cfg(test)]
mod order_index_tests {
    use darkpool_types::fuzzing::random_address;
    use types_account::order::mocks::mock_order;

    use super::*;

    #[test]
    fn test_get_all_orders() {
        let index = OrderMetadataIndex::new();
        let order_id1 = OrderId::new_v4();
        let order_id2 = OrderId::new_v4();
        let order_id3 = OrderId::new_v4();

        // Create mock orders
        let order1 = mock_order();
        let order2 = mock_order();
        let order3 = mock_order();

        // Add orders to the index
        index.add_order(order_id1, &order1, 100);
        index.add_order(order_id2, &order2, 200);
        index.add_order(order_id3, &order3, 300);

        // Get all orders and verify
        let all_orders = index.get_all_orders();
        let mut orders: Vec<OrderId> = all_orders.into_iter().collect();
        orders.sort();

        let mut expected = vec![order_id1, order_id2, order_id3];
        expected.sort();

        assert_eq!(orders, expected);
    }

    #[test]
    fn test_empty_index() {
        let index = OrderMetadataIndex::new();
        let base = random_address();
        let quote = random_address();
        let pair = Pair::new(base, quote);
        let orders = index.get_orders(&pair);
        assert!(orders.is_empty());
    }

    #[test]
    fn test_add_and_get_single_order() {
        let index = OrderMetadataIndex::new();
        let order_id = OrderId::new_v4();
        let order = mock_order();
        let pair = order.pair();

        let fillable_amount = 100;
        index.add_order(order_id, &order, fillable_amount);
        let orders = index.get_orders(&pair);
        assert_eq!(orders.len(), 1);
        assert_eq!(orders[0], order_id);
    }

    #[test]
    fn test_orders_sorted_by_amount() {
        let index = OrderMetadataIndex::new();
        let order = mock_order();
        let pair = order.pair();

        // Add orders with different matchable amounts
        let order_id1 = OrderId::new_v4();
        let order_id2 = OrderId::new_v4();
        let order_id3 = OrderId::new_v4();
        let order_id4 = OrderId::new_v4();

        index.add_order(order_id1, &order, 300);
        index.add_order(order_id2, &order, 100);
        index.add_order(order_id3, &order, 200);
        index.add_order(order_id4, &order, 400);

        let orders = index.get_orders(&pair);
        assert_eq!(orders.len(), 4);
        assert_eq!(orders[0], order_id4); // 400
        assert_eq!(orders[1], order_id1); // 300
        assert_eq!(orders[2], order_id3); // 200
        assert_eq!(orders[3], order_id2); // 100
    }

    #[test]
    fn test_different_pairs() {
        let index = OrderMetadataIndex::new();
        let order1 = mock_order();
        let order2 = mock_order();
        let pair1 = order1.pair();
        let pair2 = order2.pair();

        let order_id1 = OrderId::new_v4();
        let order_id2 = OrderId::new_v4();
        let order_id3 = OrderId::new_v4();
        let order_id4 = OrderId::new_v4();

        index.add_order(order_id1, &order1, 100);
        index.add_order(order_id2, &order2, 200);
        index.add_order(order_id3, &order1, 300);
        index.add_order(order_id4, &order2, 400);

        let orders1 = index.get_orders(&pair1);
        let orders2 = index.get_orders(&pair2);

        assert_eq!(orders1.len(), 2);
        assert_eq!(orders2.len(), 2);
    }

    #[test]
    fn test_update_matchable_amount() {
        let index = OrderMetadataIndex::new();
        let order_id = OrderId::new_v4();
        let order = mock_order();
        let pair = order.pair();

        // Add an order with an initial matchable amount
        let initial_amount = 100;
        index.add_order(order_id, &order, initial_amount);

        // Update the matchable amount
        let updated_amount = 200;
        let old_amount = index.update_matchable_amount(order_id, updated_amount);

        // Get the orders and verify the order is in the correct position
        let orders = index.get_orders(&pair);
        assert_eq!(orders.len(), 1);
        assert_eq!(orders[0], order_id);

        // Verify the updated amount by checking the internal state
        let side_index = index.index.get(&pair).unwrap();
        let sorted_vec = side_index.get(0).unwrap();
        assert_eq!(sorted_vec.0, updated_amount);

        // Verify the returned old amount
        assert_eq!(old_amount, Some(initial_amount));
    }

    #[test]
    fn test_update_matchable_amount_sort_order() {
        let index = OrderMetadataIndex::new();
        let order = mock_order();
        let pair = order.pair();

        // Add two orders with initial amounts
        let order_id1 = OrderId::new_v4();
        let order_id2 = OrderId::new_v4();

        index.add_order(order_id1, &order, 200);
        index.add_order(order_id2, &order, 100);

        // Verify initial sort order (descending by amount)
        let orders = index.get_orders(&pair);
        assert_eq!(orders.len(), 2);
        assert_eq!(orders[0], order_id1); // 200
        assert_eq!(orders[1], order_id2); // 100

        // Update order2's amount to be larger than order1
        let old_amount = index.update_matchable_amount(order_id2, 300);

        // Verify the sort order has changed
        let orders = index.get_orders(&pair);
        assert_eq!(orders.len(), 2);
        assert_eq!(orders[0], order_id2); // 300
        assert_eq!(orders[1], order_id1); // 200

        // Verify the returned old amount
        assert_eq!(old_amount, Some(100));
    }

    #[test]
    fn test_remove_order() {
        let index = OrderMetadataIndex::new();
        let order_id = OrderId::new_v4();
        let order = mock_order();
        let pair = order.pair();

        // Add an order
        index.add_order(order_id, &order, 100);

        // Verify it was added
        let orders = index.get_orders(&pair.clone());
        assert_eq!(orders.len(), 1);
        assert_eq!(orders[0], order_id);

        // Remove the order
        let result = index.remove_order(&order_id);
        assert_eq!(result, Some((pair, 100)));

        // Verify it was removed
        let orders = index.get_orders(&pair.clone());
        assert!(orders.is_empty());

        // Verify it was removed from reverse index
        let pair_and_side = index.get_pair(&order_id);
        assert!(pair_and_side.is_none());
    }

    #[test]
    fn test_remove_nonexistent_order() {
        let index = OrderMetadataIndex::new();
        let order_id = OrderId::new_v4();

        // Try to remove a nonexistent order
        let result = index.remove_order(&order_id);
        assert!(result.is_none());
    }

    #[test]
    fn test_remove_order_maintains_sort() {
        let index = OrderMetadataIndex::new();
        let order = mock_order();
        let pair = order.pair();

        // Add three orders
        let order_id1 = OrderId::new_v4();
        let order_id2 = OrderId::new_v4();
        let order_id3 = OrderId::new_v4();

        index.add_order(order_id1, &order, 300);
        index.add_order(order_id2, &order, 200);
        index.add_order(order_id3, &order, 100);

        // Remove the middle order
        let result = index.remove_order(&order_id2);
        assert_eq!(result, Some((pair, 200)));

        // Verify remaining orders are still sorted
        let orders = index.get_orders(&pair.clone());
        assert_eq!(orders.len(), 2);
        assert_eq!(orders[0], order_id1); // 300
        assert_eq!(orders[1], order_id3); // 100
    }
}
