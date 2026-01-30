//! Helpers for proposing account index changes and reading the index
//!
//! Account index updates must go through raft consensus so that the leader may
//! order them

use alloy_primitives::{Address, B256};
use circuit_types::Amount;
use types_account::{
    MatchingPoolName,
    account::{Account, OrderId},
    balance::{Balance, BalanceLocation},
    keychain::KeyChain,
    order::Order,
    order_auth::OrderAuth,
};
use types_core::{AccountId, HmacKey};
use util::res_some;

use crate::{
    StateInner, applicator::account_index::update_matchable_amounts, error::StateError,
    notifications::ProposalWaiter, state_transition::StateTransition, storage::traits::RkyvValue,
};

impl StateInner {
    // -----------
    // | Getters |
    // -----------

    /// Whether the account exists
    pub async fn contains_account(&self, id: &AccountId) -> Result<bool, StateError> {
        let id = *id;
        self.with_read_tx(move |tx| {
            let exists = tx.get_account_header(&id)?.is_some();
            Ok(exists)
        })
        .await
    }

    // --- Keychain --- //

    /// Get the symmetric key for an account
    pub async fn get_account_symmetric_key(
        &self,
        id: &AccountId,
    ) -> Result<Option<HmacKey>, StateError> {
        let id = *id;
        self.with_read_tx(move |tx| {
            let header = res_some!(tx.get_account_header(&id)?);
            let archived_key = &header.keychain.secret_keys.symmetric_key;
            let key = HmacKey::from_archived(archived_key)?;

            Ok(Some(key))
        })
        .await
    }

    /// Get the keychain for an account without deserializing the full account
    pub async fn get_account_keychain(
        &self,
        id: &AccountId,
    ) -> Result<Option<KeyChain>, StateError> {
        let id = *id;
        self.with_read_tx(move |tx| {
            let header = res_some!(tx.get_account_header(&id)?);
            let keychain = KeyChain::from_archived(&header.keychain)?;
            Ok(Some(keychain))
        })
        .await
    }

    // --- Accounts --- //

    /// Get the account with the given id
    pub async fn get_account(&self, id: &AccountId) -> Result<Option<Account>, StateError> {
        let id = *id;
        self.with_read_tx(move |tx| {
            let account = tx.get_account(&id)?;
            Ok(account)
        })
        .await
    }

    /// Get all account IDs in the state
    pub async fn get_all_account_ids(&self) -> Result<Vec<AccountId>, StateError> {
        self.with_read_tx(move |tx| {
            let account_ids = tx.get_all_account_ids()?;
            Ok(account_ids)
        })
        .await
    }

    // --- Orders --- //

    /// Get the plaintext order for a locally managed order ID
    pub async fn get_account_order(&self, id: &OrderId) -> Result<Option<Order>, StateError> {
        let id = *id;
        self.with_read_tx(move |tx| {
            let order = res_some!(tx.get_order(&id)?).deserialize()?;
            Ok(Some(order))
        })
        .await
    }

    /// Get the order authorization for a given order ID
    pub async fn get_order_auth(&self, id: &OrderId) -> Result<Option<OrderAuth>, StateError> {
        let id = *id;
        self.with_read_tx(move |tx| {
            let auth = res_some!(tx.get_order_auth(&id)?).deserialize()?;
            Ok(Some(auth))
        })
        .await
    }

    /// Get the order for a given order ID and the balance that capitalizes it
    pub async fn get_account_order_and_matchable_amount(
        &self,
        id: &OrderId,
    ) -> Result<Option<(Order, Amount)>, StateError> {
        let id = *id;
        self.with_read_tx(move |tx| {
            let order = res_some!(tx.get_order(&id)?).deserialize()?;
            let matchable_amount = tx.get_order_matchable_amount(&id)?.unwrap_or_default();
            Ok(Some((order, matchable_amount)))
        })
        .await
    }

    /// Get the account ID that contains the given intent ID
    pub async fn get_account_id_for_order(
        &self,
        intent_id: &OrderId,
    ) -> Result<Option<AccountId>, StateError> {
        let id = *intent_id;
        self.with_read_tx(move |tx| {
            let account_id = tx.get_account_id_for_order(&id)?;
            Ok(account_id)
        })
        .await
    }

    /// Get all order IDs for an account that use the given token as input
    pub async fn get_orders_with_input_token(
        &self,
        account_id: &AccountId,
        token: &Address,
    ) -> Result<Vec<OrderId>, StateError> {
        let account_id = *account_id;
        let token = *token;
        self.with_read_tx(move |tx| {
            let orders = tx.get_orders_with_input_token(&account_id, &token)?;
            Ok(orders)
        })
        .await
    }

    /// Get all orders for an account without deserializing the full account
    ///
    /// This is more efficient than calling `get_account` when only orders are
    /// needed
    pub async fn get_account_orders(
        &self,
        account_id: &AccountId,
    ) -> Result<Vec<Order>, StateError> {
        let account_id = *account_id;
        self.with_read_tx(move |tx| {
            let orders = tx.get_account_orders(&account_id)?;
            Ok(orders)
        })
        .await
    }

    /// Get the account ID for a given owner
    ///
    /// Used to route balance update events to the correct account
    pub async fn get_account_for_owner(
        &self,
        owner: &Address,
    ) -> Result<Option<AccountId>, StateError> {
        let owner = *owner;
        self.with_read_tx(move |tx| {
            let account_id = tx.get_account_for_owner(&owner)?;
            Ok(account_id)
        })
        .await
    }

    /// Get all orders across all accounts with their matching pool
    ///
    /// Returns a vector of tuples containing (AccountId, Order,
    /// MatchingPoolName) for each order in the state.
    ///
    /// Warning: this can be slow when the state has many orders
    pub async fn get_all_orders_with_matching_pool(
        &self,
    ) -> Result<Vec<(Order, AccountId, MatchingPoolName)>, StateError> {
        self.with_read_tx(move |tx| {
            let mut result = Vec::new();

            // Get all account IDs
            let account_ids = tx.get_all_account_ids()?;

            // For each account, get all orders with their metadata
            for account_id in account_ids {
                let orders = tx.get_account_orders(&account_id)?;
                for order in orders {
                    let matching_pool = tx.get_matching_pool_for_order(&order.id)?;
                    result.push((order, account_id, matching_pool));
                }
            }

            Ok(result)
        })
        .await
    }

    /// Get the order for a given intent hash
    ///
    /// Used to route public intent events to the correct order
    pub async fn get_order_for_intent_hash(
        &self,
        intent_hash: &B256,
    ) -> Result<Option<(AccountId, OrderId)>, StateError> {
        let intent_hash = *intent_hash;
        self.with_read_tx(move |tx| {
            let result = tx.get_order_for_intent_hash(&intent_hash)?;
            Ok(result)
        })
        .await
    }

    // --- Balances --- //

    /// Get the balance amount for an account and token
    pub async fn get_account_balance_value(
        &self,
        account_id: &AccountId,
        token: &Address,
        location: BalanceLocation,
    ) -> Result<Amount, StateError> {
        let account_id = *account_id;
        let token = *token;
        self.with_read_tx(move |tx| {
            let balance = tx.get_balance(&account_id, &token, location)?;
            let amt = balance.map(|b| b.amount()).unwrap_or_default();
            Ok(amt)
        })
        .await
    }

    /// Get the full state balance for an EOA located balance
    pub async fn get_account_eoa_balance(
        &self,
        account_id: &AccountId,
        token: &Address,
    ) -> Result<Option<Balance>, StateError> {
        self.get_account_balance(account_id, token, BalanceLocation::EOA).await
    }

    /// Get the full state balance for a darkpool located balance
    pub async fn get_account_darkpool_balance(
        &self,
        account_id: &AccountId,
        token: &Address,
    ) -> Result<Option<Balance>, StateError> {
        self.get_account_balance(account_id, token, BalanceLocation::Darkpool).await
    }

    /// Get the full state balance type for an account on a given token
    pub async fn get_account_balance(
        &self,
        account_id: &AccountId,
        token: &Address,
        location: BalanceLocation,
    ) -> Result<Option<Balance>, StateError> {
        let account_id = *account_id;
        let token = *token;
        self.with_read_tx(move |tx| {
            let balance = res_some!(tx.get_balance(&account_id, &token, location)?);
            let balance = balance.deserialize()?;
            Ok(Some(balance))
        })
        .await
    }

    /// Get all balances for an account without deserializing the full account
    pub async fn get_account_balances(
        &self,
        account_id: &AccountId,
    ) -> Result<Vec<Balance>, StateError> {
        let account_id = *account_id;
        self.with_read_tx(move |tx| {
            let balances = tx.get_account_balances(&account_id)?;
            Ok(balances)
        })
        .await
    }

    /// Get all tracked owners from the owner index
    ///
    /// Returns a deduplicated list of owner addresses that have balances
    pub async fn get_all_tracked_owners(&self) -> Result<Vec<Address>, StateError> {
        self.with_read_tx(|tx| {
            let entries = tx.get_all_owner_index_entries()?;
            let owners: std::collections::HashSet<_> =
                entries.into_iter().map(|(owner, _)| owner).collect();
            Ok(owners.into_iter().collect())
        })
        .await
    }

    // -----------
    // | Setters |
    // -----------

    /// Propose a new account to be added to the index
    pub async fn new_account(&self, account: Account) -> Result<ProposalWaiter, StateError> {
        assert!(account.orders.is_empty(), "use `update_account` for non-empty accounts");
        assert!(account.balances.is_empty(), "use `update_account` for non-empty balances");
        self.send_proposal(StateTransition::CreateAccount { account }).await
    }

    /// Add an order to an account
    pub async fn add_order_to_account(
        &self,
        account_id: AccountId,
        order: Order,
        auth: OrderAuth,
    ) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::AddOrderToAccount { account_id, order, auth }).await
    }

    /// Remove an order from an account
    pub async fn remove_order_from_account(
        &self,
        account_id: AccountId,
        order_id: OrderId,
    ) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::RemoveOrderFromAccount { account_id, order_id }).await
    }

    /// Update an existing order
    pub async fn update_order(&self, order: Order) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::UpdateOrder { order }).await
    }

    /// Update a balance in an account
    pub async fn update_account_balance(
        &self,
        account_id: AccountId,
        balance: types_account::balance::Balance,
    ) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::UpdateAccountBalance { account_id, balance }).await
    }

    /// Update the matching engine cache for orders affected by a balance change
    ///
    /// This method updates the matching engine's in-memory cache without
    /// persisting to DB or going through raft consensus. It should be called
    /// before `update_account_balance` to enable low-latency matching while
    /// the raft proposal is in flight.
    pub async fn update_matching_engine_for_balance(
        &self,
        account_id: AccountId,
        balance: &Balance,
    ) -> Result<(), StateError> {
        let token = balance.mint();
        let balance_amount = balance.amount();
        let engine = self.matching_engine.clone();

        self.with_read_tx(move |tx| {
            update_matchable_amounts(&engine, tx, account_id, &token, balance_amount)?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod test {
    use types_account::{
        account::mocks::mock_empty_account, order::mocks::mock_order,
        order_auth::mocks::mock_order_auth,
    };

    use crate::test_helpers::mock_state;

    /// Test creating an account
    #[tokio::test]
    async fn test_new_account() {
        let state = mock_state().await;

        let account = mock_empty_account();
        let waiter = state.new_account(account.clone()).await.unwrap();
        waiter.await.unwrap();

        // Check for the account in the state
        let retrieved_account = state.get_account(&account.id).await.unwrap().unwrap();
        assert_eq!(retrieved_account.id, account.id);
    }

    /// Test adding a local order to an account
    #[tokio::test]
    async fn test_add_order_to_account() {
        let state = mock_state().await;

        let account = mock_empty_account();
        let waiter = state.new_account(account.clone()).await.unwrap();
        waiter.await.unwrap();

        // Add a local order to the account
        let order = mock_order();
        let auth = mock_order_auth();
        let waiter = state.add_order_to_account(account.id, order.clone(), auth).await.unwrap();
        waiter.await.unwrap();

        // Verify the account was updated
        let retrieved_account = state.get_account(&account.id).await.unwrap().unwrap();
        assert_eq!(retrieved_account.id, account.id);
        assert!(retrieved_account.orders.contains_key(&order.id));
    }

    /// Test removing an order from an account
    #[tokio::test]
    async fn test_remove_order_from_account() {
        let state = mock_state().await;

        let account = mock_empty_account();
        let waiter = state.new_account(account.clone()).await.unwrap();
        waiter.await.unwrap();

        // Add a local order to the account
        let order = mock_order();
        let auth = mock_order_auth();
        let waiter = state.add_order_to_account(account.id, order.clone(), auth).await.unwrap();
        waiter.await.unwrap();

        // Verify the order was added
        let retrieved_account = state.get_account(&account.id).await.unwrap().unwrap();
        assert!(retrieved_account.orders.contains_key(&order.id));

        // Remove the order from the account
        let waiter = state.remove_order_from_account(account.id, order.id).await.unwrap();
        waiter.await.unwrap();

        // Verify the order was removed
        let retrieved_account = state.get_account(&account.id).await.unwrap().unwrap();
        assert!(!retrieved_account.orders.contains_key(&order.id));
    }
}
