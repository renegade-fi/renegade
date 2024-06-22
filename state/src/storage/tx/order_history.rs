//! Storage access methods for order metadata

use common::types::wallet::{order_metadata::OrderMetadata, OrderIdentifier, WalletIdentifier};
use libmdbx::{TransactionKind, RW};

use crate::{storage::error::StorageError, ORDER_HISTORY_TABLE};

use super::StateTxn;

/// Error message emitted when a duplicate order is found
const ERR_DUPLICATE_ORDER: &str = "Duplicate order";
/// Error message emitted when a given order is not found
const ERR_ORDER_NOT_FOUND: &str = "Order not found";

/// Get the key for a given wallet's order history
fn order_history_key(wallet_id: &WalletIdentifier) -> String {
    format!("order-history/{wallet_id}")
}

// -----------
// | Getters |
// -----------

impl<'db, T: TransactionKind> StateTxn<'db, T> {
    /// Get metadata for a given order
    #[allow(clippy::needless_pass_by_value)]
    pub fn get_order_metadata(
        &self,
        wallet_id: WalletIdentifier,
        order_id: OrderIdentifier,
    ) -> Result<Option<OrderMetadata>, StorageError> {
        let orders = self.get_order_history(&wallet_id)?;
        Ok(orders.iter().find(|o| o.id == order_id).cloned())
    }

    /// Get the orders for a given wallet
    ///
    /// Sorted by descending creation time
    pub fn get_order_history(
        &self,
        wallet_id: &WalletIdentifier,
    ) -> Result<Vec<OrderMetadata>, StorageError> {
        let key = order_history_key(wallet_id);
        let mut orders: Vec<OrderMetadata> =
            self.inner.read(ORDER_HISTORY_TABLE, &key)?.unwrap_or_default();
        orders.sort_by_key(|o| std::cmp::Reverse(o.created));

        Ok(orders)
    }

    /// Get up to `n` most recent orders for a given wallet
    pub fn get_order_history_truncated(
        &self,
        n: usize,
        wallet_id: &WalletIdentifier,
    ) -> Result<Vec<OrderMetadata>, StorageError> {
        let mut orders = self.get_order_history(wallet_id)?;
        orders.truncate(n);
        Ok(orders)
    }
}

// -----------
// | Setters |
// -----------

impl<'db> StateTxn<'db, RW> {
    /// Append an order to the order history
    pub fn push_order_history(
        &self,
        wallet_id: &WalletIdentifier,
        metadata: OrderMetadata,
    ) -> Result<(), StorageError> {
        let mut orders = self.get_order_history(wallet_id)?;

        // Check for a duplicate
        if orders.iter().any(|o| o.id == metadata.id) {
            return Err(StorageError::Other(ERR_DUPLICATE_ORDER.to_string()));
        }

        // Push to the front of the list
        orders.insert(0, metadata);
        self.write_order_history(wallet_id, orders)
    }

    /// Update an order in the order history
    pub fn update_order_metadata(
        &self,
        wallet_id: &WalletIdentifier,
        metadata: OrderMetadata,
    ) -> Result<(), StorageError> {
        let mut orders = self.get_order_history(wallet_id)?;
        let index = orders.iter().position(|o| o.id == metadata.id);
        if index.is_none() {
            return Err(StorageError::Other(ERR_ORDER_NOT_FOUND.to_string()));
        }

        orders[index.unwrap()] = metadata;
        self.write_order_history(wallet_id, orders)
    }

    /// Write the order history for a given wallet
    #[allow(clippy::needless_pass_by_value)]
    fn write_order_history(
        &self,
        wallet_id: &WalletIdentifier,
        orders: Vec<OrderMetadata>,
    ) -> Result<(), StorageError> {
        let key = order_history_key(wallet_id);
        self.inner.write(ORDER_HISTORY_TABLE, &key, &orders)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Reverse;

    use common::types::{
        wallet::order_metadata::{OrderMetadata, OrderState},
        wallet_mocks::mock_order,
        TimestampedPrice,
    };
    use itertools::Itertools;
    use rand::{thread_rng, Rng, RngCore};
    use uuid::Uuid;

    use crate::test_helpers::mock_db;

    /// Create a single random order metadata instance
    fn random_order_md() -> OrderMetadata {
        let mut rng = thread_rng();
        OrderMetadata {
            id: Uuid::new_v4(),
            state: OrderState::Created,
            fills: vec![],
            created: rng.next_u64(),
            data: mock_order(),
        }
    }

    /// Create a random set of order metadata
    fn random_order_history(n: usize) -> Vec<OrderMetadata> {
        (0..n).map(|_| random_order_md()).collect_vec()
    }

    /// Test appending and retrieving order metadata
    #[test]
    fn test_append_orders() {
        const N: usize = 1000;
        let db = mock_db();
        let wallet_id = Uuid::new_v4();
        let mut history = random_order_history(N);

        let tx = db.new_write_tx().unwrap();
        for order_md in history.iter().cloned() {
            tx.push_order_history(&wallet_id, order_md).unwrap();
        }
        tx.commit().unwrap();

        // Sort the history by descending creation time
        history.sort_by_key(|o| Reverse(o.created));

        let tx = db.new_read_tx().unwrap();
        let orders = tx.get_order_history(&wallet_id).unwrap();
        assert_eq!(orders, history);

        // Get the first 10 orders
        let tx = db.new_read_tx().unwrap();
        let orders = tx.get_order_history_truncated(10, &wallet_id).unwrap();
        assert_eq!(orders.len(), 10);
        assert_eq!(orders, history[..10].to_vec());
    }

    /// Tests updating an order in the history
    #[test]
    fn test_update_order() {
        const N: usize = 1000;
        let db = mock_db();
        let wallet_id = Uuid::new_v4();
        let history = random_order_history(N);

        // Setup the history
        let tx = db.new_write_tx().unwrap();
        for order_md in history.iter().cloned() {
            tx.push_order_history(&wallet_id, order_md).unwrap();
        }
        tx.commit().unwrap();

        // Choose a random order
        let mut rng = rand::thread_rng();
        let index = rng.gen_range(0..history.len());
        let curr_order = history[index].clone();

        // Check the current state of that order
        let tx = db.new_read_tx().unwrap();
        let order = tx.get_order_metadata(wallet_id, curr_order.id).unwrap().unwrap();
        assert_eq!(order, curr_order);

        // Update the order
        let mut updated_order = curr_order;
        let amount = rng.gen();
        let price = TimestampedPrice::new(100.2);
        updated_order.record_partial_fill(amount, price);

        let tx = db.new_write_tx().unwrap();
        tx.update_order_metadata(&wallet_id, updated_order.clone()).unwrap();
        tx.commit().unwrap();

        // Get the updated order
        let tx = db.new_read_tx().unwrap();
        let order = tx.get_order_metadata(wallet_id, updated_order.id).unwrap().unwrap();
        assert_eq!(order, updated_order);
    }
}
