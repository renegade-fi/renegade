//! A cache for common predicates evaluated on the order book
//!
//! E.g. querying orders which are (externally) matchable, or querying open
//! orders on a given asset

use circuit_types::Amount;
use dashmap::DashSet;
use tracing::instrument;
use types_account::{
    account::{OrderId, pair::Pair},
    order::Order,
};

use crate::{
    caching::order_metadata_index::OrderMetadataIndex,
    storage::{db::DB, error::StorageError},
};

use super::matchable_amount::MatchableAmountMap;

/// A filter for querying the order book cache
#[derive(Clone, Debug)]
pub struct OrderBookFilter {
    /// The pair to filter on
    ///
    /// In order (input_token, output_token)
    pair: Pair,
    /// Whether to only accept externally matchable orders
    external: bool,
}

impl OrderBookFilter {
    /// Construct a new order book filter
    pub fn new(pair: Pair, external: bool) -> Self {
        Self { pair, external }
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
    externally_enabled_orders: DashSet<OrderId>,
    /// The index of order metadata
    order_metadata_index: OrderMetadataIndex,
    /// Mapping of matchable amount at the midpoint of a pair
    matchable_amount_map: MatchableAmountMap,
}

impl OrderBookCache {
    /// Construct a new order book cache
    pub fn new() -> Self {
        Self {
            externally_enabled_orders: DashSet::new(),
            order_metadata_index: OrderMetadataIndex::new(),
            matchable_amount_map: MatchableAmountMap::new(),
        }
    }

    // --- Getters --- //

    /// Get orders matching a filter
    pub fn get_orders(&self, filter: &OrderBookFilter) -> Vec<OrderId> {
        let orders = self.order_metadata_index.get_orders(&filter.pair);
        if filter.external {
            orders.into_iter().filter(|id| self.externally_enabled_orders.contains(id)).collect()
        } else {
            orders
        }
    }

    /// Returns whether an order exists in the cache
    pub fn order_exists(&self, id: OrderId) -> bool {
        self.order_metadata_index.order_exists(&id)
    }

    /// Get all orders that match any filter
    pub fn get_all_orders(&self) -> Vec<OrderId> {
        self.order_metadata_index.get_all_orders()
    }

    /// Get the matchable amount for both sides of a pair
    ///
    /// Returns (buy_amount, sell_amount) where buy amount is denominated in the
    /// quote token, sell amount is denominated in the base token
    pub fn get_matchable_amount(&self, pair: &Pair) -> (Amount, Amount) {
        self.matchable_amount_map.get(pair)
    }

    // --- Setters --- //

    /// Add an order to the cache
    pub fn add_order(&self, order: &Order, matchable_amount: Amount) {
        self.order_metadata_index.add_order(order.id, order, matchable_amount);
        if order.allow_external_matches() {
            self.externally_enabled_orders.insert(order.id);
            self.matchable_amount_map.add_amount(order.pair(), matchable_amount);
        }
    }

    /// Update an order in the cache
    pub fn update_order(&self, id: OrderId, matchable_amount: Amount) {
        let pair = self.order_metadata_index.get_pair(&id).unwrap();

        // Update the index and get the previous matchable amount
        let old_amount =
            self.order_metadata_index.update_matchable_amount(id, matchable_amount).unwrap_or(0);

        if self.externally_enabled_orders.contains(&id) {
            // Update the matchable amount map with the delta
            if old_amount > matchable_amount {
                let delta = old_amount.saturating_sub(matchable_amount);
                self.matchable_amount_map.sub_amount(pair, delta);
            } else {
                let delta = matchable_amount.saturating_sub(old_amount);
                self.matchable_amount_map.add_amount(pair, delta);
            }
        }
    }

    /// Mark an order as externally matchable
    pub fn mark_order_externally_matchable(&self, order: &Order) {
        self.externally_enabled_orders.insert(order.id);
    }

    /// Remove an order from the cache entirely
    pub fn remove_order(&self, id: OrderId) {
        let maybe_info = self.order_metadata_index.remove_order(&id);
        if maybe_info.is_none() {
            return;
        }
        let (pair, matchable_amount) = maybe_info.unwrap();

        if self.externally_enabled_orders.remove(&id).is_some() {
            self.matchable_amount_map.sub_amount(pair, matchable_amount);
        }
    }

    /// Remove an externally enabled order
    pub fn remove_externally_enabled_order(&self, order: OrderId) {
        self.externally_enabled_orders.remove(&order);
    }

    /// Backfill the order cache from a DB
    ///
    /// This method may be used to populate the cache on startup
    #[instrument(skip(self, _db))]
    pub fn hydrate_from_db(&self, _db: &DB) -> Result<(), StorageError> {
        // TODO: Implement order book storage
        // let tx = db.new_read_tx()?;
        // let orders = tx.get_local_orders()?;
        // for order_id in orders.into_iter() {
        //     // Fetch order info and check if the order is ready for matching
        //     let info = match tx.get_order_info(&order_id)? {
        //         Some(info) => info,
        //         None => continue,
        //     };

        //     if info.local && info.ready_for_match() {
        //         // Get the order itself
        //         let wallet = match tx.get_wallet_for_order(&order_id)? {
        //             Some(wallet) => wallet,
        //             None => continue,
        //         };

        //         let order = match wallet.get_order(&order_id) {
        //             Some(order) => order,
        //             None => continue,
        //         };

        //         let matchable_amount =
        //             wallet.get_balance_for_order(order).map(|b|
        // b.amount).unwrap_or_default();         self.add_order(order_id,
        // order, matchable_amount).await;     }
        // }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use types_account::order::mocks::{mock_order, mock_order_with_pair};

    use super::*;

    /// Tests getting an order by pair
    #[test]
    fn test_get_orders_basic() {
        let cache = OrderBookCache::new();
        let order = mock_order();
        let order_id = order.id;
        let pair = order.pair();

        // Add an order to the cache
        cache.add_order(&order, 100 /* matchable_amount */);

        let filter = OrderBookFilter::new(pair, false /* external */);
        let orders = cache.get_orders(&filter);
        assert_eq!(orders.len(), 1);
        assert_eq!(orders[0], order_id);

        // Remove the order from the cache
        cache.remove_order(order_id);
        let orders = cache.get_orders(&filter);
        assert_eq!(orders.len(), 0);
    }

    /// Tests getting multiple orders by their pair
    #[test]
    fn test_get_orders_multiple() {
        let cache = OrderBookCache::new();
        let order1 = mock_order();
        let pair = order1.pair();
        let order2 = mock_order_with_pair(pair);
        let order3 = mock_order_with_pair(pair);

        cache.add_order(&order1, 100 /* matchable_amount */);
        cache.add_order(&order2, 300 /* matchable_amount */);
        cache.add_order(&order3, 200 /* matchable_amount */);

        let filter = OrderBookFilter::new(pair, false /* external */);
        let orders = cache.get_orders(&filter);
        assert_eq!(orders.len(), 3);
        assert_eq!(orders, vec![order2.id, order3.id, order1.id]);

        // Remove the middle order
        cache.remove_order(order3.id);
        let orders = cache.get_orders(&filter);
        assert_eq!(orders.len(), 2);
        assert_eq!(orders, vec![order2.id, order1.id]);
    }

    // TODO: Implement external orders
    // /// Tests getting external orders only
    // #[test]
    // fn test_get_orders_external() {
    //     let cache = OrderBookCache::new();
    //     let order_id1 = OrderId::new_v4();
    //     let order_id2 = OrderId::new_v4();
    //     let order_id3 = OrderId::new_v4();
    //     let mut order1 = mock_order();
    //     let mut order2 = order1.clone();
    //     let mut order3 = order1.clone();
    //     order1.allow_external_matches = true;
    //     order2.allow_external_matches = false;
    //     order3.allow_external_matches = true;

    //     cache.add_order(order_id1, &order1, 100 /* matchable_amount */).await;
    //     cache.add_order(order_id2, &order2, 200 /* matchable_amount */).await;
    //     cache.add_order(order_id3, &order3, 300 /* matchable_amount */).await;

    //     let filter = OrderBookFilter::new(order1.pair(), order1.side, true /*
    // external */);     let orders = cache.get_orders(filter.clone()).await;
    //     assert_eq!(orders.len(), 2);
    //     assert_eq!(orders, vec![order_id3, order_id1]);

    //     // Remove the first order
    //     cache.remove_order(order_id1).await;
    //     let orders = cache.get_orders(filter).await;
    //     assert_eq!(orders.len(), 1);
    //     assert_eq!(orders, vec![order_id3]);
    // }

    /// Tests getting orders on different pairs
    #[test]
    fn test_get_orders_different_pairs() {
        let cache = OrderBookCache::new();
        let order1 = mock_order();
        let order2 = mock_order();
        let pair1 = order1.pair();
        let pair2 = order2.pair();
        let order3 = mock_order_with_pair(pair1);

        cache.add_order(&order1, 300 /* matchable_amount */);
        cache.add_order(&order2, 100 /* matchable_amount */);
        cache.add_order(&order3, 200 /* matchable_amount */);

        // Check the first pair
        let filter1 = OrderBookFilter::new(pair1, false /* external */);
        let orders = cache.get_orders(&filter1);
        assert_eq!(orders.len(), 2);
        assert_eq!(orders, vec![order1.id, order3.id]);

        // Check the second pair
        let filter2 = OrderBookFilter::new(pair2, false /* external */);
        let orders = cache.get_orders(&filter2);
        assert_eq!(orders.len(), 1);
        assert_eq!(orders, vec![order2.id]);

        // Remove from the first pair
        cache.remove_order(order1.id);
        let orders = cache.get_orders(&filter1);
        assert_eq!(orders.len(), 1);
        assert_eq!(orders, vec![order3.id]);

        // Remove from the second pair
        cache.remove_order(order2.id);
        let orders = cache.get_orders(&filter2);
        assert_eq!(orders.len(), 0);
    }
}
