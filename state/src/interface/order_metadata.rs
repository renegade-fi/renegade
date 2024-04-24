//! State interface methods for order metadata

use common::types::wallet::{order_metadata::OrderMetadata, OrderIdentifier, WalletIdentifier};
use util::res_some;

use crate::{
    error::StateError, notifications::ProposalWaiter, storage::error::StorageError, State,
    StateTransition,
};

/// The error message emitted when a wallet cannot be found for an order
pub const ERR_MISSING_WALLET: &str = "Wallet not found for order";

impl State {
    // -----------
    // | Getters |
    // -----------

    /// Get the metadata for an order
    pub fn get_order_metadata(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<Option<OrderMetadata>, StateError> {
        let tx = self.db.new_read_tx()?;
        let wallet_id = tx
            .get_wallet_for_order(order_id)?
            .ok_or(StateError::Db(StorageError::NotFound(ERR_MISSING_WALLET.to_string())))?;
        let md = res_some!(tx.get_order_metadata(wallet_id, *order_id)?);
        tx.commit()?;

        Ok(Some(md))
    }

    /// Get a history of the wallet's orders
    pub fn get_order_history(
        &self,
        n: usize,
        wallet_id: &WalletIdentifier,
    ) -> Result<Vec<OrderMetadata>, StateError> {
        let tx = self.db.new_read_tx()?;
        let orders = tx.get_order_history_truncated(n, wallet_id)?;
        tx.commit()?;

        Ok(orders)
    }

    // -----------
    // | Setters |
    // -----------

    /// Update the state of an order in a wallet
    pub fn update_order_metadata(&self, meta: OrderMetadata) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::UpdateOrderMetadata { meta })
    }
}

#[cfg(test)]
mod test {
    use std::cmp::Reverse;

    use common::types::wallet::order_metadata::OrderState;
    use itertools::Itertools;
    use rand::{seq::IteratorRandom, thread_rng, RngCore};

    use crate::{storage::db::DB, test_helpers::mock_state};

    use super::*;

    /// Get a random order metadata instance
    fn random_metadata() -> OrderMetadata {
        let mut rng = thread_rng();
        OrderMetadata {
            id: OrderIdentifier::new_v4(),
            state: OrderState::Created,
            filled: 0,
            created: rng.next_u64(),
        }
    }

    /// Setup an order history using the given orders and wallet id
    fn setup_order_history(wallet_id: &WalletIdentifier, orders: &[OrderMetadata], db: &DB) {
        // Add orders to the history
        let tx = db.new_write_tx().unwrap();
        orders.iter().for_each(|o| tx.push_order_history(wallet_id, *o).unwrap());
        let order_ids = orders.iter().map(|o| o.id).collect_vec();
        tx.index_orders(wallet_id, &order_ids).unwrap();
        tx.commit().unwrap();
    }

    /// Tests updating order history and metadata
    #[test]
    fn test_order_history() {
        const N: usize = 100;
        let state = mock_state();
        let mut orders = (0..N).map(|_| random_metadata()).collect_vec();
        let wallet_id = WalletIdentifier::new_v4();

        setup_order_history(&wallet_id, &orders, &state.db);
        orders.sort_by_key(|o| Reverse(o.created));

        // Get back the order history
        let n = 10;
        let history = state.get_order_history(n, &wallet_id).unwrap();
        assert_eq!(orders[..n], history);

        // Read back a random order's metadata
        let idx = (0..orders.len()).choose(&mut thread_rng()).unwrap();
        let meta = orders[idx];
        let found = state.get_order_metadata(&meta.id).unwrap().unwrap();
        assert_eq!(meta, found);
    }

    /// Test updating an order's metadata    
    #[tokio::test]
    async fn test_update_order_metadata() {
        const N: usize = 100;
        let state = mock_state();
        let orders = (0..N).map(|_| random_metadata()).collect_vec();
        let wallet_id = WalletIdentifier::new_v4();

        setup_order_history(&wallet_id, &orders, &state.db);

        // Modify a single order's metadata
        let idx = (0..orders.len()).choose(&mut thread_rng()).unwrap();
        let mut meta = orders[idx];
        meta.filled += 1;

        // Update and retrieve the order's metadata
        let waiter = state.update_order_metadata(meta).unwrap();
        waiter.await.unwrap();
        let fetched_meta = state.get_order_metadata(&meta.id).unwrap().unwrap();
        assert_eq!(meta, fetched_meta);
    }
}
