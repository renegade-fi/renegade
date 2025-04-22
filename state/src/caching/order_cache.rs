//! A cache for common predicates evaluated on the order book
//!
//! E.g. querying orders which are (externally) matchable, or querying open
//! orders on a given asset

use std::collections::HashSet;

use circuit_types::{order::OrderSide, Amount};
use common::types::wallet::{Order, OrderIdentifier, Pair};
use tokio::sync::RwLock;
use tracing::instrument;

use crate::storage::{db::DB, error::StorageError};

use super::{
    matchable_amount::MatchableAmountMap, order_metadata_index::OrderMetadataIndex, RwLockHashSet,
};

/// A filter for querying the order book cache
#[derive(Clone, Debug)]
pub struct OrderBookFilter {
    /// The pair to filter on
    pair: Pair,
    /// The side to filter on
    side: OrderSide,
    /// Whether to only accept externally matchable orders
    external: bool,
}

impl OrderBookFilter {
    /// Construct a new order book filter
    pub fn new(pair: Pair, side: OrderSide, external: bool) -> Self {
        Self { pair, side, external }
    }
}

/// The order book cache
#[derive(Default)]
pub struct OrderBookCache {
    /// The set of local orders which have external matches enabled
    ///
    /// This may not be a subset of `matchable_orders`, some externally
    /// matchable orders may not be yet matchable, e.g. if they are waiting for
    /// validity proofs
    externally_enabled_orders: RwLockHashSet<OrderIdentifier>,
    /// The index of order metadata
    order_metadata_index: OrderMetadataIndex,
    /// Mapping of matchable amount at the midpoint of a pair
    matchable_amount_map: MatchableAmountMap,
}

impl OrderBookCache {
    /// Construct a new order book cache
    pub fn new() -> Self {
        Self {
            externally_enabled_orders: RwLock::new(HashSet::new()),
            order_metadata_index: OrderMetadataIndex::new(),
            matchable_amount_map: MatchableAmountMap::new(),
        }
    }

    // --- Getters --- //

    /// Get orders matching a filter
    pub async fn get_orders(&self, filter: OrderBookFilter) -> Vec<OrderIdentifier> {
        let orders = self.order_metadata_index.get_orders(&filter.pair, filter.side).await;
        if filter.external {
            let externally_matchable = self.externally_enabled_orders.read().await;
            orders.into_iter().filter(|id| externally_matchable.contains(id)).collect()
        } else {
            orders
        }
    }

    /// Returns whether an order exists in the cache
    pub fn order_exists(&self, id: OrderIdentifier) -> bool {
        self.order_metadata_index.order_exists(&id)
    }

    /// Get all orders that match any filter
    pub async fn get_all_orders(&self) -> Vec<OrderIdentifier> {
        self.order_metadata_index.get_all_orders().await
    }

    // --- Setters --- //

    /// Add an order to the cache
    pub async fn add_order(&self, id: OrderIdentifier, order: &Order, matchable_amount: Amount) {
        self.order_metadata_index.add_order(id, order, matchable_amount).await;
        if order.allow_external_matches {
            self.externally_enabled_orders.write().await.insert(id);
        }
        let (pair, side) = order.pair_and_side();
        self.matchable_amount_map.add_amount(pair, side, matchable_amount).await;
    }

    /// Add an order to the cache in a blocking fashion
    pub fn add_order_blocking(&self, id: OrderIdentifier, order: &Order, matchable_amount: Amount) {
        let rt = tokio::runtime::Handle::current();
        rt.block_on(self.add_order(id, order, matchable_amount));

        if order.allow_external_matches {
            self.externally_enabled_orders.blocking_write().insert(id);
        }
    }

    /// Update an order in the cache
    pub async fn update_order(&self, id: OrderIdentifier, matchable_amount: Amount) {
        let (pair, side) = self.order_metadata_index.get_pair_and_side(&id).await.unwrap();

        // Update the index and get the previous matchable amount
        let old_amount = self
            .order_metadata_index
            .update_matchable_amount(id, matchable_amount)
            .await
            .unwrap_or(0);

        // Update the matchable amount map with the delta
        if old_amount > matchable_amount {
            let delta = old_amount.saturating_sub(matchable_amount);
            self.matchable_amount_map.sub_amount(pair, side, delta).await;
        } else {
            let delta = matchable_amount.saturating_sub(old_amount);
            self.matchable_amount_map.add_amount(pair, side, delta).await;
        }
    }

    /// Update an order in the cache in a blocking fashion
    pub fn update_order_blocking(&self, id: OrderIdentifier, matchable_amount: Amount) {
        let rt = tokio::runtime::Handle::current();
        rt.block_on(self.update_order(id, matchable_amount));
    }

    /// Mark an order as externally matchable
    pub async fn mark_order_externally_matchable(&self, order: OrderIdentifier) {
        self.externally_enabled_orders.write().await.insert(order);
    }

    /// Mark an order as externally matchable in a blocking fashion
    pub fn mark_order_externally_matchable_blocking(&self, order: OrderIdentifier) {
        self.externally_enabled_orders.blocking_write().insert(order);
    }

    /// Remove an order from the cache entirely
    pub async fn remove_order(&self, order: OrderIdentifier) {
        let (pair, side) = self.order_metadata_index.get_pair_and_side(&order).await.unwrap();
        let removed = self.order_metadata_index.remove_order(&order).await.unwrap_or(0);
        self.matchable_amount_map.sub_amount(pair, side, removed).await;
        self.externally_enabled_orders.write().await.remove(&order);
    }

    /// Remove an order in a blocking fashion
    pub fn remove_order_blocking(&self, order: OrderIdentifier) {
        let rt = tokio::runtime::Handle::current();
        rt.block_on(self.remove_order(order));

        self.remove_externally_enabled_order_blocking(order);
    }

    /// Remove an externally enabled order
    pub async fn remove_externally_enabled_order(&self, order: OrderIdentifier) {
        self.externally_enabled_orders.write().await.remove(&order);
    }

    /// Remove an externally enabled order in a blocking fashion
    pub fn remove_externally_enabled_order_blocking(&self, order: OrderIdentifier) {
        self.externally_enabled_orders.blocking_write().remove(&order);
    }

    /// Backfill the order cache from a DB
    ///
    /// This method may be used to populate the cache on startup
    #[instrument(skip(self, db))]
    pub async fn hydrate_from_db(&self, db: &DB) -> Result<(), StorageError> {
        let tx = db.new_read_tx()?;
        let orders = tx.get_local_orders()?;
        for order_id in orders.into_iter() {
            // Fetch order info and check if the order is ready for matching
            let info = match tx.get_order_info(&order_id)? {
                Some(info) => info,
                None => continue,
            };

            if info.local && info.ready_for_match() {
                // Get the order itself
                let wallet = match tx.get_wallet_for_order(&order_id)? {
                    Some(wallet) => wallet,
                    None => continue,
                };

                let order = match wallet.get_order(&order_id) {
                    Some(order) => order,
                    None => continue,
                };

                let matchable_amount =
                    wallet.get_balance_for_order(order).map(|b| b.amount).unwrap_or_default();
                self.add_order(order_id, order, matchable_amount).await;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use common::types::wallet_mocks::mock_order;

    /// Tests getting an order by pair
    #[tokio::test]
    async fn test_get_orders_basic() {
        let cache = OrderBookCache::new();
        let order_id = OrderIdentifier::new_v4();
        let order = mock_order();

        // Add an order to the cache
        cache.add_order(order_id, &order, 100 /* matchable_amount */).await;

        let filter = OrderBookFilter::new(order.pair(), order.side, false /* external */);
        let orders = cache.get_orders(filter.clone()).await;
        assert_eq!(orders.len(), 1);
        assert_eq!(orders[0], order_id);

        // Remove the order from the cache
        cache.remove_order(order_id).await;
        let orders = cache.get_orders(filter).await;
        assert_eq!(orders.len(), 0);
    }

    /// Tests getting multiple orders by their pair
    #[tokio::test]
    async fn test_get_orders_multiple() {
        let cache = OrderBookCache::new();
        let order_id1 = OrderIdentifier::new_v4();
        let order_id2 = OrderIdentifier::new_v4();
        let order_id3 = OrderIdentifier::new_v4();
        let order = mock_order();

        cache.add_order(order_id1, &order, 100 /* matchable_amount */).await;
        cache.add_order(order_id2, &order, 300 /* matchable_amount */).await;
        cache.add_order(order_id3, &order, 200 /* matchable_amount */).await;

        let filter = OrderBookFilter::new(order.pair(), order.side, false /* external */);
        let orders = cache.get_orders(filter.clone()).await;
        assert_eq!(orders.len(), 3);
        assert_eq!(orders, vec![order_id2, order_id3, order_id1]);

        // Remove the middle order
        cache.remove_order(order_id3).await;
        let orders = cache.get_orders(filter).await;
        assert_eq!(orders.len(), 2);
        assert_eq!(orders, vec![order_id2, order_id1]);
    }

    /// Tests getting external orders only
    #[tokio::test]
    async fn test_get_orders_external() {
        let cache = OrderBookCache::new();
        let order_id1 = OrderIdentifier::new_v4();
        let order_id2 = OrderIdentifier::new_v4();
        let order_id3 = OrderIdentifier::new_v4();
        let mut order1 = mock_order();
        let mut order2 = order1.clone();
        let mut order3 = order1.clone();
        order1.allow_external_matches = true;
        order2.allow_external_matches = false;
        order3.allow_external_matches = true;

        cache.add_order(order_id1, &order1, 100 /* matchable_amount */).await;
        cache.add_order(order_id2, &order2, 200 /* matchable_amount */).await;
        cache.add_order(order_id3, &order3, 300 /* matchable_amount */).await;

        let filter = OrderBookFilter::new(order1.pair(), order1.side, true /* external */);
        let orders = cache.get_orders(filter.clone()).await;
        assert_eq!(orders.len(), 2);
        assert_eq!(orders, vec![order_id3, order_id1]);

        // Remove the first order
        cache.remove_order(order_id1).await;
        let orders = cache.get_orders(filter).await;
        assert_eq!(orders.len(), 1);
        assert_eq!(orders, vec![order_id3]);
    }

    /// Tests getting orders on different pairs
    #[tokio::test]
    async fn test_get_orders_different_pairs() {
        let cache = OrderBookCache::new();
        let order_id1 = OrderIdentifier::new_v4();
        let order_id2 = OrderIdentifier::new_v4();
        let order_id3 = OrderIdentifier::new_v4();
        let order1 = mock_order();
        let order2 = mock_order();
        let order3 = order1.clone();

        cache.add_order(order_id1, &order1, 300 /* matchable_amount */).await;
        cache.add_order(order_id2, &order2, 100 /* matchable_amount */).await;
        cache.add_order(order_id3, &order3, 200 /* matchable_amount */).await;

        // Check the first pair
        let filter1 = OrderBookFilter::new(order1.pair(), order1.side, false /* external */);
        let orders = cache.get_orders(filter1.clone()).await;
        assert_eq!(orders.len(), 2);
        assert_eq!(orders, vec![order_id1, order_id3]);

        // Check the second pair
        let filter2 = OrderBookFilter::new(order2.pair(), order2.side, false /* external */);
        let orders = cache.get_orders(filter2.clone()).await;
        assert_eq!(orders.len(), 1);
        assert_eq!(orders, vec![order_id2]);

        // Remove from the first pair
        cache.remove_order(order_id1).await;
        let orders = cache.get_orders(filter1).await;
        assert_eq!(orders.len(), 1);
        assert_eq!(orders, vec![order_id3]);

        // Remove from the second pair
        cache.remove_order(order_id2).await;
        let orders = cache.get_orders(filter2).await;
        assert_eq!(orders.len(), 0);
    }
}
