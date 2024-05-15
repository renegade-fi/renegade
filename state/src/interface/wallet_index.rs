//! Helpers for proposing wallet index changes and reading the index
//!
//! Wallet index updates must go through raft consensus so that the leader may
//! order them

use circuit_types::order::Order;
use common::types::{
    tasks::QueuedTask,
    wallet::{OrderIdentifier, Wallet, WalletIdentifier},
};
use util::res_some;

use crate::{error::StateError, notifications::ProposalWaiter, State, StateTransition};

impl State {
    // -----------
    // | Getters |
    // -----------

    /// Whether the wallet exists
    pub async fn contains_wallet(&self, id: &WalletIdentifier) -> Result<bool, StateError> {
        Ok(self.get_wallet(id).await?.is_some())
    }

    /// Get the wallet with the given id
    pub async fn get_wallet(&self, id: &WalletIdentifier) -> Result<Option<Wallet>, StateError> {
        let id = *id;
        self.with_read_tx(move |tx| {
            let wallet = tx.get_wallet(&id)?;
            Ok(wallet)
        })
        .await
    }

    /// Get the wallet and the tasks in the queue for the wallet
    ///
    /// Defined here to manage these in a single tx
    pub async fn get_wallet_and_tasks(
        &self,
        id: &WalletIdentifier,
    ) -> Result<Option<(Wallet, Vec<QueuedTask>)>, StateError> {
        let id = *id;
        self.with_read_tx(move |tx| {
            let wallet = res_some!(tx.get_wallet(&id)?);
            let tasks = tx.get_queued_tasks(&id)?;
            Ok(Some((wallet, tasks)))
        })
        .await
    }

    /// Get the plaintext order for a locally managed order ID
    pub async fn get_managed_order(
        &self,
        id: &OrderIdentifier,
    ) -> Result<Option<Order>, StateError> {
        let id = *id;
        self.with_read_tx(move |tx| {
            let wallet_id = res_some!(tx.get_wallet_for_order(&id)?);
            let wallet = res_some!(tx.get_wallet(&wallet_id)?);
            Ok(wallet.orders.get(&id).cloned())
        })
        .await
    }

    /// Get the wallet that contains the given order ID
    pub async fn get_wallet_for_order(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<Option<WalletIdentifier>, StateError> {
        let oid = *order_id;
        self.with_read_tx(move |tx| {
            let wallet_id = tx.get_wallet_for_order(&oid)?;
            Ok(wallet_id)
        })
        .await
    }

    /// Get the ids of all wallets managed by the local relayer
    pub async fn get_all_wallets(&self) -> Result<Vec<Wallet>, StateError> {
        self.with_read_tx(move |tx| {
            let wallets = tx.get_all_wallets()?;
            Ok(wallets)
        })
        .await
    }

    // -----------
    // | Setters |
    // -----------

    /// Propose a new wallet to be added to the index
    pub async fn new_wallet(&self, wallet: Wallet) -> Result<ProposalWaiter, StateError> {
        assert!(wallet.orders.is_empty(), "use `update-wallet` for non-empty wallets");
        self.send_proposal(StateTransition::AddWallet { wallet }).await
    }

    /// Update a wallet in the index
    pub async fn update_wallet(&self, wallet: Wallet) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::UpdateWallet { wallet }).await
    }
}

#[cfg(test)]
mod test {
    // --- Order History Tests --- //
    // We test order history updates here to give access to state interfaces
    // Wallet update handlers in the applicator handle order history changes to
    // hide the wallet index/order history denormalization

    use circuit_types::balance::Balance;
    use common::types::{
        wallet::{
            order_metadata::{OrderMetadata, OrderState},
            OrderIdentifier, WalletIdentifier,
        },
        wallet_mocks::{mock_empty_wallet, mock_order},
    };
    use itertools::Itertools;
    use num_bigint::BigUint;

    use crate::{order_history::test::setup_order_history, test_helpers::mock_state, State};

    /// Create a set of mock historical orders
    fn create_mock_historical_orders(n: usize, wallet_id: WalletIdentifier, state: &State) {
        let history = (0..n)
            .map(|_| OrderMetadata {
                id: OrderIdentifier::new_v4(),
                state: OrderState::Filled,
                filled: 1,
                created: 0,
                data: mock_order(),
            })
            .collect_vec();

        setup_order_history(&wallet_id, &history, &state.db);
    }

    /// Test creating a wallet with an order
    #[tokio::test]
    #[allow(non_snake_case)]
    async fn test_order_history__new_wallet() {
        let state = mock_state().await;

        let mut wallet = mock_empty_wallet();
        let order = mock_order();
        let order_id = OrderIdentifier::new_v4();
        wallet.add_order(order_id, order.clone()).unwrap();

        // Add the wallet to state
        let waiter = state.update_wallet(wallet.clone()).await.unwrap();
        waiter.await.unwrap();

        // Check the order history for a wallet
        let history = state.get_order_history(10, &wallet.wallet_id).await.unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].id, order_id);
        assert_eq!(history[0].state, OrderState::Created);
    }

    /// Tests that updating a wallet marks all orders in the history as
    /// `Created`
    #[tokio::test]
    #[allow(non_snake_case)]
    async fn test_order_history__existing_order() {
        let state = mock_state().await;
        let mut wallet = mock_empty_wallet();
        let order = mock_order();
        let order_id = OrderIdentifier::new_v4();
        wallet.add_order(order_id, order.clone()).unwrap();

        // Update the wallet
        let waiter = state.update_wallet(wallet.clone()).await.unwrap();
        waiter.await.unwrap();

        // Mark the order's state in the history as `Matching`, simulating an order that
        // now has validity proofs ready for match
        let mut meta = state.get_order_metadata(&order_id).await.unwrap().unwrap();
        meta.state = OrderState::Matching;
        let waiter = state.update_order_metadata(meta).await.unwrap();
        waiter.await.unwrap();

        // Update the wallet
        wallet.add_balance(Balance::new_from_mint(BigUint::from(1u8))).unwrap();
        let waiter = state.update_wallet(wallet.clone()).await.unwrap();
        waiter.await.unwrap();

        // Check the order history
        let history = state.get_order_history(10, &wallet.wallet_id).await.unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].id, order_id);
        // The order should now be back in the `Created` state, awaiting new proofs
        assert_eq!(history[0].state, OrderState::Created);
    }

    /// Test updating a wallet in which we cancel one order and replace with
    /// another
    #[tokio::test]
    #[allow(non_snake_case)]
    async fn test_order_history__cancel_replace() {
        const N: usize = 100;
        let state = mock_state().await;
        let mut wallet = mock_empty_wallet();

        // Setup a longer mock order history of filled orders
        create_mock_historical_orders(N, wallet.wallet_id, &state);

        // Add an existing order
        let order_id = OrderIdentifier::new_v4();
        let order = mock_order();
        wallet.add_order(order_id, order).unwrap();

        // Update the wallet
        let waiter = state.update_wallet(wallet.clone()).await.unwrap();
        waiter.await.unwrap();

        // Now remove this order and add another
        wallet.remove_order(&order_id).unwrap();
        let order_id2 = OrderIdentifier::new_v4();
        let order = mock_order();
        wallet.add_order(order_id2, order).unwrap();

        // Update the wallet
        let waiter = state.update_wallet(wallet.clone()).await.unwrap();
        waiter.await.unwrap();

        // Now fetch history, it should contain one order in the `Created` state
        // and another in the `Cancelled` state
        let history = state.get_order_history(10, &wallet.wallet_id).await.unwrap();
        assert_eq!(history.len(), 10);
        assert_eq!(history[0].id, order_id2);
        assert_eq!(history[0].state, OrderState::Created);
        assert_eq!(history[1].id, order_id);
        assert_eq!(history[1].state, OrderState::Cancelled);

        // The rest of the orders should be unaffected
        assert!(history[2..].iter().all(|meta| meta.state == OrderState::Filled));
    }
}
