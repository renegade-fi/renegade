//! A cache for common predicates evaluated on the order book
//!
//! E.g. querying orders which are (externally) matchable, or querying open
//! orders on a given asset

use std::collections::HashSet;

use common::types::wallet::OrderIdentifier;
use tokio::sync::RwLock;

/// The order book cache
#[derive(Default)]
pub struct OrderBookCache {
    /// The set of open orders which are matchable and locally managed
    matchable_orders: RwLock<HashSet<OrderIdentifier>>,
    /// The set of local orders which have external matches enabled
    ///
    /// This may not be a subset of `matchable_orders`, some externally
    /// matchable orders may not be yet matchable, e.g. if they are waiting for
    /// validity proofs
    externally_enabled_orders: RwLock<HashSet<OrderIdentifier>>,
}

impl OrderBookCache {
    /// Construct a new order book cache
    pub fn new() -> Self {
        Self {
            matchable_orders: RwLock::new(HashSet::new()),
            externally_enabled_orders: RwLock::new(HashSet::new()),
        }
    }

    // --- Getters --- //

    /// Get the set of matchable orders
    pub async fn matchable_orders(&self) -> Vec<OrderIdentifier> {
        self.matchable_orders.read().await.iter().copied().collect()
    }

    /// Get the set of matchable orders in a blocking fashion
    pub fn matchable_orders_blocking(&self) -> Vec<OrderIdentifier> {
        self.matchable_orders.blocking_read().iter().copied().collect()
    }

    /// Get the set of externally matchable orders
    ///
    /// This is the intersection of `matchable_orders` and
    /// `externally_enabled_orders`
    pub async fn externally_matchable_orders(&self) -> Vec<OrderIdentifier> {
        let matchable = self.matchable_orders.read().await;
        let external = self.externally_enabled_orders.read().await;
        matchable.intersection(&external).copied().collect()
    }

    /// Get the set of externally matchable orders in a blocking fashion
    pub fn externally_matchable_orders_blocking(&self) -> Vec<OrderIdentifier> {
        let matchable = self.matchable_orders.blocking_read();
        let external = self.externally_enabled_orders.blocking_read();
        matchable.intersection(&external).copied().collect()
    }

    // --- Setters --- //

    /// Add a matchable order
    pub async fn add_matchable_order(&self, order: OrderIdentifier) {
        self.matchable_orders.write().await.insert(order);
    }

    /// Add a matchable order in a blocking fashion
    pub fn add_matchable_order_blocking(&self, order: OrderIdentifier) {
        self.matchable_orders.blocking_write().insert(order);
    }

    /// Add an externally enabled order
    pub async fn add_externally_enabled_order(&self, order: OrderIdentifier) {
        self.externally_enabled_orders.write().await.insert(order);
    }

    /// Add an externally enabled order in a blocking fashion
    pub fn add_externally_enabled_order_blocking(&self, order: OrderIdentifier) {
        self.externally_enabled_orders.blocking_write().insert(order);
    }

    /// Remove an order from the cache entirely
    pub async fn remove_order(&self, order: OrderIdentifier) {
        self.matchable_orders.write().await.remove(&order);
        self.externally_enabled_orders.write().await.remove(&order);
    }

    /// Remove an order in a blocking fashion
    pub fn remove_order_blocking(&self, order: OrderIdentifier) {
        self.remove_matchable_order_blocking(order);
        self.remove_externally_enabled_order_blocking(order);
    }

    /// Remove a matchable order
    pub async fn remove_matchable_order(&self, order: OrderIdentifier) {
        self.matchable_orders.write().await.remove(&order);
    }

    /// Remove a matchable order in a blocking fashion
    pub fn remove_matchable_order_blocking(&self, order: OrderIdentifier) {
        self.matchable_orders.blocking_write().remove(&order);
    }

    /// Remove an externally enabled order
    pub async fn remove_externally_enabled_order(&self, order: OrderIdentifier) {
        self.externally_enabled_orders.write().await.remove(&order);
    }

    /// Remove an externally enabled order in a blocking fashion
    pub fn remove_externally_enabled_order_blocking(&self, order: OrderIdentifier) {
        self.externally_enabled_orders.blocking_write().remove(&order);
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;
    use std::hash::Hash;

    use super::OrderBookCache;
    use uuid::Uuid;

    /// Returns whether two vectors contain the same elements, ignoring order
    fn same_elements<T: Eq + Hash>(a: Vec<T>, b: Vec<T>) -> bool {
        let a: HashSet<_> = a.into_iter().collect();
        let b: HashSet<_> = b.into_iter().collect();
        a == b
    }

    /// Tests the `get_matchable_orders` method
    #[test]
    fn test_get_matchable_orders() {
        let cache = OrderBookCache::new();
        let order1 = Uuid::new_v4();
        let order2 = Uuid::new_v4();

        // Add the first order as matchable and the second as externally enabled
        cache.add_matchable_order_blocking(order1);
        cache.add_externally_enabled_order_blocking(order2);

        assert_eq!(cache.matchable_orders_blocking(), vec![order1]);

        // Remove the second order, this should not affect the matchable orders
        cache.remove_order_blocking(order2);
        assert_eq!(cache.matchable_orders_blocking(), vec![order1]);

        // Remove the first order, the matchable orders should now be empty
        cache.remove_matchable_order_blocking(order1);
        assert_eq!(cache.matchable_orders_blocking(), vec![]);
    }

    /// Tests the `externally_matchable_orders` method
    #[test]
    fn test_externally_matchable_orders() {
        let cache = OrderBookCache::new();
        let order1 = Uuid::new_v4();
        let order2 = Uuid::new_v4();

        // Add the first order as externally enabled and the second as matchable
        cache.add_matchable_order_blocking(order1);
        cache.add_externally_enabled_order_blocking(order1);
        cache.add_matchable_order_blocking(order2);

        assert_eq!(cache.externally_matchable_orders_blocking(), vec![order1]);

        // Remove the second order, this should not affect externally enabled orders
        cache.remove_order_blocking(order2);
        assert_eq!(cache.externally_matchable_orders_blocking(), vec![order1]);

        // Remove the first order, externally enabled orders should now be empty
        cache.remove_externally_enabled_order_blocking(order1);
        assert_eq!(cache.externally_matchable_orders_blocking(), vec![]);
    }

    /// Tests the `order_cache` methods
    #[test]
    fn test_order_cache_multiple() {
        let cache = OrderBookCache::new();
        let order1 = Uuid::new_v4();
        let order2 = Uuid::new_v4();
        let order3 = Uuid::new_v4();

        // Add orders
        cache.add_matchable_order_blocking(order1);
        cache.add_externally_enabled_order_blocking(order2);
        cache.add_matchable_order_blocking(order3);
        cache.add_externally_enabled_order_blocking(order3);

        // Two are matchable, only one is externally matchable
        assert!(same_elements(cache.matchable_orders_blocking(), vec![order1, order3]));
        assert_eq!(cache.externally_matchable_orders_blocking(), vec![order3]);

        // Remove the first order, only one is matchable
        cache.remove_order_blocking(order1);
        assert_eq!(cache.matchable_orders_blocking(), vec![order3]);
        assert_eq!(cache.externally_matchable_orders_blocking(), vec![order3]);

        // Remove the last order, none are matchable
        cache.remove_order_blocking(order3);
        assert_eq!(cache.matchable_orders_blocking(), vec![]);
        assert_eq!(cache.externally_matchable_orders_blocking(), vec![]);
    }
}
