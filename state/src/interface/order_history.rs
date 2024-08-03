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
    pub async fn get_order_metadata(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<Option<OrderMetadata>, StateError> {
        let oid = *order_id;
        self.with_read_tx(move |tx| {
            let wallet_id = tx
                .get_wallet_for_order(&oid)?
                .ok_or(StateError::Db(StorageError::NotFound(ERR_MISSING_WALLET.to_string())))?;
            let md = res_some!(tx.get_order_metadata(wallet_id, oid)?);
            Ok(Some(md))
        })
        .await
    }

    /// Get a truncated history of the wallet's orders
    pub async fn get_order_history(
        &self,
        n: usize,
        wallet_id: &WalletIdentifier,
    ) -> Result<Vec<OrderMetadata>, StateError> {
        let wallet_id = *wallet_id;
        self.with_read_tx(move |tx| {
            let orders = tx.get_order_history_truncated(n, &wallet_id)?;
            Ok(orders)
        })
        .await
    }

    // -----------
    // | Setters |
    // -----------

    /// Update the state of an order in a wallet
    pub async fn update_order_metadata(
        &self,
        meta: OrderMetadata,
    ) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::UpdateOrderMetadata { meta }).await
    }
}

#[cfg(test)]
pub mod test {
    use std::cmp::Reverse;

    use common::types::{
        wallet::order_metadata::OrderState, wallet_mocks::mock_order, TimestampedPrice,
    };
    use itertools::Itertools;
    use rand::{seq::IteratorRandom, thread_rng, RngCore};

    use crate::{storage::db::DB, test_helpers::mock_state};

    use super::*;

    /// Get a random order metadata instance
    pub fn random_metadata() -> OrderMetadata {
        let mut rng = thread_rng();
        let data = mock_order();
        OrderMetadata {
            id: OrderIdentifier::new_v4(),
            data,
            state: OrderState::Created,
            fills: vec![],
            created: rng.next_u64(),
        }
    }

    /// Setup an order history using the given orders and wallet id
    pub fn setup_order_history(wallet_id: &WalletIdentifier, orders: &[OrderMetadata], db: &DB) {
        // Add orders to the history
        let tx = db.new_write_tx().unwrap();
        orders.iter().cloned().for_each(|o| tx.push_order_history(wallet_id, o).unwrap());
        let order_ids = orders.iter().map(|o| o.id).collect_vec();
        tx.index_orders(wallet_id, &order_ids).unwrap();
        tx.commit().unwrap();
    }

    /// Tests updating order history and metadata
    #[tokio::test]
    async fn test_order_history() {
        const N: usize = 100;
        let state = mock_state().await;
        let mut orders = (0..N).map(|_| random_metadata()).collect_vec();
        let wallet_id = WalletIdentifier::new_v4();

        setup_order_history(&wallet_id, &orders, &state.db);
        orders.sort_by_key(|o| Reverse(o.created));

        // Get back the order history
        let n = 10;
        let history = state.get_order_history(n, &wallet_id).await.unwrap();
        assert_eq!(orders[..n], history);

        // Read back a random order's metadata
        let idx = (0..orders.len()).choose(&mut thread_rng()).unwrap();
        let meta = orders[idx].clone();
        let found = state.get_order_metadata(&meta.id).await.unwrap().unwrap();
        assert_eq!(meta, found);
    }

    /// Test updating an order's metadata    
    #[tokio::test]
    async fn test_update_order_metadata() {
        const N: usize = 100;
        let state = mock_state().await;
        let orders = (0..N).map(|_| random_metadata()).collect_vec();
        let wallet_id = WalletIdentifier::new_v4();

        setup_order_history(&wallet_id, &orders, &state.db);

        // Modify a single order's metadata
        let idx = (0..orders.len()).choose(&mut thread_rng()).unwrap();
        let mut meta = orders[idx].clone();
        let amount = 1;
        let price = TimestampedPrice::new(10.);
        meta.record_partial_fill(amount, price);

        // Update and retrieve the order's metadata
        let waiter = state.update_order_metadata(meta.clone()).await.unwrap();
        waiter.await.unwrap();
        let fetched_meta = state.get_order_metadata(&meta.id).await.unwrap().unwrap();
        assert_eq!(meta, fetched_meta);
    }
}
