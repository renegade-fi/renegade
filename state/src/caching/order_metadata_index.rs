//! Indexing of orders by metadata
//!
//! Specifically, we build an efficiently queryable mapping from pair -> side ->
//! (matchable_amount, order_id)
//!
//! This allows the matching engine to efficiently query a narrow set of
//! candidate orders to match against a target order.

use std::collections::HashMap;

use circuit_types::{order::OrderSide, Amount};
use common::types::wallet::{Order, OrderIdentifier, Pair};
use tokio::sync::RwLock;

use super::RwLockHashMap;

/// A type alias for a the inner index mapping
type OrderSideIndex = HashMap<OrderSide, SortedVec<(Amount, OrderIdentifier)>>;

/// The order metadata index
#[derive(Default)]
pub struct OrderMetadataIndex {
    /// The mapping from pair -> side -> (matchable_amount, order_id)
    index: RwLockHashMap<Pair, OrderSideIndex>,
    /// A reverse mapping from order_id to pair and side
    ///
    /// This is used to efficiently query the index by order_id for updates and
    /// deletion
    reverse_index: RwLockHashMap<OrderIdentifier, (Pair, OrderSide)>,
}

impl OrderMetadataIndex {
    /// Construct a new order metadata index
    pub fn new() -> Self {
        let index = RwLock::new(HashMap::new());
        let reverse_index = RwLock::new(HashMap::new());
        Self { index, reverse_index }
    }

    // --- Getters --- //

    /// Get all orders for a given pair and side, sorted by matchable amount
    pub async fn get_orders(&self, pair: &Pair, side: OrderSide) -> Vec<OrderIdentifier> {
        let index = self.index.read().await;
        let orders_vec = index.get(pair).and_then(|side_index| side_index.get(&side));
        match orders_vec {
            Some(v) => v.iter().map(|(_, oid)| *oid).collect(),
            None => Vec::new(),
        }
    }

    /// Get all orders in the index
    ///
    /// No sort ordering is guaranteed, given that the units on which individual
    /// orders are sorted may differ
    pub async fn get_all_orders(&self) -> Vec<OrderIdentifier> {
        self.reverse_index.read().await.keys().copied().collect()
    }

    /// Get the pair and side for a given order_id
    pub async fn get_pair_and_side(&self, order_id: &OrderIdentifier) -> Option<(Pair, OrderSide)> {
        self.reverse_index.read().await.get(order_id).cloned()
    }

    // --- Setters --- //

    /// Add an order to the index
    pub async fn add_order(
        &self,
        order_id: OrderIdentifier,
        order: &Order,
        matchable_amount: Amount,
    ) {
        let (pair, side) = order.pair_and_side();
        let mut index = self.index.write().await;
        let entry = index.entry(pair.clone()).or_insert_with(OrderSideIndex::new);
        entry.entry(side).or_insert_with(SortedVec::new).insert((matchable_amount, order_id));

        // Update the reverse index
        let mut reverse_index = self.reverse_index.write().await;
        reverse_index.insert(order_id, (pair, side));
    }

    /// Update the matchable amount for an order
    pub async fn update_matchable_amount(
        &self,
        order_id: OrderIdentifier,
        matchable_amount: Amount,
    ) {
        let (pair, side) = self.get_pair_and_side(&order_id).await.unwrap();
        let mut index = self.index.write().await;
        let entry = index.entry(pair).or_insert_with(OrderSideIndex::new);
        let sorted_vec = entry.entry(side).or_insert_with(SortedVec::new);

        // Remove the old entry
        if let Some(idx) = sorted_vec.find_index(|(_, oid)| *oid == order_id) {
            sorted_vec.remove(idx);
        }

        // Insert the new entry (this will maintain the sort order)
        sorted_vec.insert((matchable_amount, order_id));
    }

    /// Remove an order from the index
    ///
    /// Note that we do not clean up sub-index entries when their
    /// lists become empty.
    pub async fn remove_order(&self, order_id: &OrderIdentifier) -> Option<()> {
        // Get the pair and side from the reverse index
        let (pair, side) = self.get_pair_and_side(order_id).await?;

        // Remove from the main index
        let mut index = self.index.write().await;
        let side_index = index.get_mut(&pair)?;
        let sorted_vec = side_index.get_mut(&side)?;

        if let Some(idx) = sorted_vec.find_index(|(_, oid)| oid == order_id) {
            sorted_vec.remove(idx);
        }

        // Remove from the reverse index
        let mut reverse_index = self.reverse_index.write().await;
        reverse_index.remove(order_id);

        Some(())
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
    use rand::{seq::SliceRandom, thread_rng, Rng};

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
    use super::*;
    use circuit_types::Address;
    use common::types::wallet_mocks::mock_order;

    #[tokio::test]
    async fn test_get_all_orders() {
        let index = OrderMetadataIndex::new();
        let order_id1 = OrderIdentifier::new_v4();
        let order_id2 = OrderIdentifier::new_v4();
        let order_id3 = OrderIdentifier::new_v4();

        // Create mock orders
        let order1 = mock_order();
        let order2 = mock_order();
        let order3 = mock_order();

        // Add orders to the index
        index.add_order(order_id1, &order1, 100).await;
        index.add_order(order_id2, &order2, 200).await;
        index.add_order(order_id3, &order3, 300).await;

        // Get all orders and verify
        let all_orders = index.get_all_orders().await;
        let mut orders: Vec<OrderIdentifier> = all_orders.into_iter().collect();
        orders.sort();

        let mut expected = vec![order_id1, order_id2, order_id3];
        expected.sort();

        assert_eq!(orders, expected);
    }

    #[tokio::test]
    async fn test_empty_index() {
        let index = OrderMetadataIndex::new();
        let base = Address::from(1u8);
        let quote = Address::from(2u8);
        let pair = (base, quote);
        let orders = index.get_orders(&pair, OrderSide::Buy).await;
        assert!(orders.is_empty());
    }

    #[tokio::test]
    async fn test_add_and_get_single_order() {
        let index = OrderMetadataIndex::new();
        let order_id = OrderIdentifier::new_v4();
        let order = mock_order();
        let pair = order.pair();

        let fillable_amount = 100;
        index.add_order(order_id, &order, fillable_amount).await;
        let orders = index.get_orders(&pair, OrderSide::Buy).await;
        assert_eq!(orders.len(), 1);
        assert_eq!(orders[0], order_id);
    }

    #[tokio::test]
    async fn test_orders_sorted_by_amount() {
        let index = OrderMetadataIndex::new();
        let order = mock_order();
        let pair = order.pair();

        // Add orders with different matchable amounts
        let order_id1 = OrderIdentifier::new_v4();
        let order_id2 = OrderIdentifier::new_v4();
        let order_id3 = OrderIdentifier::new_v4();
        let order_id4 = OrderIdentifier::new_v4();

        index.add_order(order_id1, &order, 300).await;
        index.add_order(order_id2, &order, 100).await;
        index.add_order(order_id3, &order, 200).await;
        index.add_order(order_id4, &order, 400).await;

        let orders = index.get_orders(&pair, OrderSide::Buy).await;
        assert_eq!(orders.len(), 4);
        assert_eq!(orders[0], order_id4); // 400
        assert_eq!(orders[1], order_id1); // 300
        assert_eq!(orders[2], order_id3); // 200
        assert_eq!(orders[3], order_id2); // 100
    }

    #[tokio::test]
    async fn test_different_pairs_and_sides() {
        let index = OrderMetadataIndex::new();
        let order1 = mock_order();
        let mut order2 = mock_order();
        order2.side = order1.side.opposite();
        let pair1 = order1.pair();
        let pair2 = order2.pair();

        let order_id1 = OrderIdentifier::new_v4();
        let order_id2 = OrderIdentifier::new_v4();
        let order_id3 = OrderIdentifier::new_v4();
        let order_id4 = OrderIdentifier::new_v4();

        index.add_order(order_id1, &order1, 100).await;
        index.add_order(order_id2, &order2, 200).await;
        index.add_order(order_id3, &order1, 300).await;
        index.add_order(order_id4, &order2, 400).await;

        let orders1_correct_side = index.get_orders(&pair1, order1.side).await;
        let orders1_incorrect_side = index.get_orders(&pair1, order1.side.opposite()).await;
        let orders2_correct_side = index.get_orders(&pair2, order2.side).await;
        let orders2_incorrect_side = index.get_orders(&pair2, order2.side.opposite()).await;

        assert_eq!(orders1_correct_side.len(), 2);
        assert!(orders1_incorrect_side.is_empty());
        assert_eq!(orders2_correct_side.len(), 2);
        assert!(orders2_incorrect_side.is_empty());
    }

    #[tokio::test]
    async fn test_update_matchable_amount() {
        let index = OrderMetadataIndex::new();
        let order_id = OrderIdentifier::new_v4();
        let order = mock_order();
        let pair = order.pair();

        // Add an order with an initial matchable amount
        let initial_amount = 100;
        index.add_order(order_id, &order, initial_amount).await;

        // Update the matchable amount
        let updated_amount = 200;
        index.update_matchable_amount(order_id, updated_amount).await;

        // Get the orders and verify the order is in the correct position
        let orders = index.get_orders(&pair, order.side).await;
        assert_eq!(orders.len(), 1);
        assert_eq!(orders[0], order_id);

        // Verify the updated amount by checking the internal state
        let index_map = index.index.read().await;
        let side_index = index_map.get(&pair).unwrap();
        let sorted_vec = side_index.get(&OrderSide::Buy).unwrap();
        assert_eq!(sorted_vec.get(0).unwrap().0, updated_amount);
    }

    #[tokio::test]
    async fn test_update_matchable_amount_sort_order() {
        let index = OrderMetadataIndex::new();
        let order = mock_order();
        let pair = order.pair();

        // Add two orders with initial amounts
        let order_id1 = OrderIdentifier::new_v4();
        let order_id2 = OrderIdentifier::new_v4();

        index.add_order(order_id1, &order, 200).await;
        index.add_order(order_id2, &order, 100).await;

        // Verify initial sort order (descending by amount)
        let orders = index.get_orders(&pair, OrderSide::Buy).await;
        assert_eq!(orders.len(), 2);
        assert_eq!(orders[0], order_id1); // 200
        assert_eq!(orders[1], order_id2); // 100

        // Update order2's amount to be larger than order1
        index.update_matchable_amount(order_id2, 300).await;

        // Verify the sort order has changed
        let orders = index.get_orders(&pair, OrderSide::Buy).await;
        assert_eq!(orders.len(), 2);
        assert_eq!(orders[0], order_id2); // 300
        assert_eq!(orders[1], order_id1); // 200
    }

    #[tokio::test]
    async fn test_remove_order() {
        let index = OrderMetadataIndex::new();
        let order_id = OrderIdentifier::new_v4();
        let order = mock_order();
        let pair = order.pair();

        // Add an order
        index.add_order(order_id, &order, 100).await;

        // Verify it was added
        let orders = index.get_orders(&pair, order.side).await;
        assert_eq!(orders.len(), 1);
        assert_eq!(orders[0], order_id);

        // Remove the order
        let result = index.remove_order(&order_id).await;
        assert!(result.is_some());

        // Verify it was removed
        let orders = index.get_orders(&pair, order.side).await;
        assert!(orders.is_empty());

        // Verify it was removed from reverse index
        let pair_and_side = index.get_pair_and_side(&order_id).await;
        assert!(pair_and_side.is_none());
    }

    #[tokio::test]
    async fn test_remove_nonexistent_order() {
        let index = OrderMetadataIndex::new();
        let order_id = OrderIdentifier::new_v4();

        // Try to remove a nonexistent order
        let result = index.remove_order(&order_id).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_remove_order_maintains_sort() {
        let index = OrderMetadataIndex::new();
        let order = mock_order();
        let pair = order.pair();

        // Add three orders
        let order_id1 = OrderIdentifier::new_v4();
        let order_id2 = OrderIdentifier::new_v4();
        let order_id3 = OrderIdentifier::new_v4();

        index.add_order(order_id1, &order, 300).await;
        index.add_order(order_id2, &order, 200).await;
        index.add_order(order_id3, &order, 100).await;

        // Remove the middle order
        index.remove_order(&order_id2).await;

        // Verify remaining orders are still sorted
        let orders = index.get_orders(&pair, OrderSide::Buy).await;
        assert_eq!(orders.len(), 2);
        assert_eq!(orders[0], order_id1); // 300
        assert_eq!(orders[1], order_id3); // 100
    }
}
