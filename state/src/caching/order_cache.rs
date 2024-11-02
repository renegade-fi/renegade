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
    /// The set of open orders which are _externally_ matchable and locally
    /// managed
    ///
    /// This should be a subset of `matchable_orders`
    externally_matchable_orders: RwLock<HashSet<OrderIdentifier>>,
}

impl OrderBookCache {
    /// Construct a new order book cache
    pub fn new() -> Self {
        Self {
            matchable_orders: RwLock::new(HashSet::new()),
            externally_matchable_orders: RwLock::new(HashSet::new()),
        }
    }

    // --- Getters --- //

    /// Get the set of matchable orders
    pub async fn matchable_orders(&self) -> Vec<OrderIdentifier> {
        self.matchable_orders.read().await.iter().copied().collect()
    }

    /// Get the set of externally matchable orders
    pub async fn externally_matchable_orders(&self) -> Vec<OrderIdentifier> {
        self.externally_matchable_orders.read().await.iter().copied().collect()
    }

    // --- Setters --- //

    /// Add a matchable order
    pub async fn add_matchable_order(&self, order: OrderIdentifier) {
        self.matchable_orders.write().await.insert(order);
    }

    /// Add an externally matchable order
    pub async fn add_externally_matchable_order(&self, order: OrderIdentifier) {
        self.externally_matchable_orders.write().await.insert(order);
    }

    /// Remove a matchable order
    pub async fn remove_matchable_order(&self, order: OrderIdentifier) {
        self.matchable_orders.write().await.remove(&order);
    }

    /// Remove an externally matchable order
    pub async fn remove_externally_matchable_order(&self, order: OrderIdentifier) {
        self.externally_matchable_orders.write().await.remove(&order);
    }
}
