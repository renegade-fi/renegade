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
}

impl OrderMetadataIndex {
    /// Construct a new order metadata index
    pub fn new() -> Self {
        let index = RwLock::new(HashMap::new());
        Self { index }
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
        let entry = index.entry(pair).or_insert_with(OrderSideIndex::new);
        entry.entry(side).or_insert_with(SortedVec::new).insert((matchable_amount, order_id));
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

    /// Get the vector
    #[allow(unused)]
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
}
