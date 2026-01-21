//! Helpers for proposing account index changes and reading the index
//!
//! Account index updates must go through raft consensus so that the leader may
//! order them

use circuit_types::Amount;
use types_account::{
    account::{Account, OrderId},
    keychain::KeyChain,
    order::Order,
    order_auth::OrderAuth,
};
use types_core::{AccountId, HmacKey};
use util::res_some;

use crate::{
    StateInner, error::StateError, notifications::ProposalWaiter,
    state_transition::StateTransition, storage::traits::RkyvValue,
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

    /// Get the account with the given id
    pub async fn get_account(&self, id: &AccountId) -> Result<Option<Account>, StateError> {
        let id = *id;
        self.with_read_tx(move |tx| {
            let account = tx.get_account(&id)?;
            Ok(account)
        })
        .await
    }

    /// Get the plaintext order for a locally managed order ID
    pub async fn get_managed_order(&self, id: &OrderId) -> Result<Option<Order>, StateError> {
        let id = *id;
        self.with_read_tx(move |tx| {
            let order = res_some!(tx.get_order(&id)?).deserialize()?;
            Ok(Some(order))
        })
        .await
    }

    /// Get the order for a given order ID and the balance that capitalizes it
    pub async fn get_managed_order_and_matchable_amount(
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
