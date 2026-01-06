//! Helpers for proposing account index changes and reading the index
//!
//! Account index updates must go through raft consensus so that the leader may
//! order them

use darkpool_types::balance::Balance;
use types_account::{
    account::{Account, OrderId},
    order::Order,
};
use types_core::AccountId;
use types_tasks::QueuedTask;
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
            let exists = tx.get_account(&id)?.is_some();
            Ok(exists)
        })
        .await
    }

    /// Get the account with the given id
    pub async fn get_account(&self, id: &AccountId) -> Result<Option<Account>, StateError> {
        let id = *id;
        self.with_read_tx(move |tx| {
            let account_value = res_some!(tx.get_account(&id)?);
            let account = account_value.deserialize()?;
            Ok(Some(account))
        })
        .await
    }

    /// Get the account and the tasks in the queue for the account
    ///
    /// Defined here to manage these in a single tx
    pub async fn get_account_and_tasks(
        &self,
        id: &AccountId,
    ) -> Result<Option<(Account, Vec<QueuedTask>)>, StateError> {
        let id = *id;
        self.with_read_tx(move |tx| {
            // Read the account's task queue
            let account_value = res_some!(tx.get_account(&id)?);
            let account = account_value.deserialize()?;
            let queue = tx.get_task_queue(&id)?;

            // Fetch the tasks one by one
            let mut tasks = Vec::new();
            if let Some(queue) = queue {
                for task_id in queue.all_tasks() {
                    if let Some(task_value) = tx.get_task(&task_id)? {
                        let task = task_value.deserialize()?;
                        tasks.push(task);
                    }
                }
            }

            Ok(Some((account, tasks)))
        })
        .await
    }

    /// Get the plaintext order for a locally managed order ID
    pub async fn get_managed_order(&self, id: &OrderId) -> Result<Option<Order>, StateError> {
        let id = *id;
        self.with_read_tx(move |tx| {
            let account_value = res_some!(tx.get_account_for_intent(&id)?);
            let account = account_value.deserialize()?;
            Ok(account.orders.get(&id).cloned())
        })
        .await
    }

    /// Get the order for a given order ID and the balance that capitalizes it
    pub async fn get_managed_order_and_balance(
        &self,
        id: &OrderId,
    ) -> Result<Option<(Order, Balance)>, StateError> {
        let id = *id;
        self.with_read_tx(move |tx| {
            let account = res_some!(tx.get_account_for_intent(&id)?);
            let archived_order = res_some!(account.orders.get(&id));
            let order = Order::from_archived(archived_order)?;

            // Get the balance that capitalizes the order
            let sell_mint = &archived_order.intent.in_token;
            let balance = match account.balances.get(sell_mint) {
                Some(b) => Balance::from_archived(b)?,
                None => Balance::default(),
            };

            Ok(Some((order, balance)))
        })
        .await
    }

    /// Get the account ID that contains the given intent ID
    pub async fn get_account_id_for_intent(
        &self,
        intent_id: &OrderId,
    ) -> Result<Option<AccountId>, StateError> {
        let id = *intent_id;
        self.with_read_tx(move |tx| {
            let account_id = tx.get_account_id_for_intent(&id)?;
            Ok(account_id)
        })
        .await
    }

    /// Get the account that contains the given intent ID
    pub async fn get_account_for_intent(
        &self,
        intent_id: &OrderId,
    ) -> Result<Option<Account>, StateError> {
        let iid = *intent_id;
        self.with_read_tx(move |tx| {
            let account_value = res_some!(tx.get_account_for_intent(&iid)?);
            let account = account_value.deserialize()?;
            Ok(Some(account))
        })
        .await
    }

    /// Get all the accounts managed by the local relayer
    pub async fn get_all_accounts(&self) -> Result<Vec<Account>, StateError> {
        self.with_read_tx(move |tx| {
            let accounts = tx.get_all_accounts()?;
            let accounts = accounts
                .into_iter()
                .map(|account_value| account_value.deserialize())
                .collect::<Result<Vec<Account>, _>>()?;
            Ok(accounts)
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

    /// Update an account in the index
    pub async fn update_account(&self, account: Account) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::UpdateAccount { account }).await
    }
}

#[cfg(test)]
mod test {
    use types_account::{account::mocks::mock_empty_account, order::mocks::mock_order};

    use crate::test_helpers::mock_state;

    /// Test creating an account
    #[tokio::test]
    async fn test_new_account() {
        let state = mock_state().await;

        let account = mock_empty_account();
        let waiter = state.new_account(account.clone()).await.unwrap();
        waiter.await.unwrap();

        // Check for the account in the state
        let retrieved_account = state.get_account(&account.wallet_id).await.unwrap().unwrap();
        assert_eq!(retrieved_account.wallet_id, account.wallet_id);
    }

    /// Test updating an account
    #[tokio::test]
    async fn test_update_account() {
        let state = mock_state().await;

        let account = mock_empty_account();
        let waiter = state.new_account(account.clone()).await.unwrap();
        waiter.await.unwrap();

        // Update the account
        let mut updated_account = account.clone();
        let order = mock_order();
        updated_account.orders.insert(order.id, order);
        // Verify the account was updated
        let retrieved_account = state.get_account(&account.wallet_id).await.unwrap().unwrap();
        assert_eq!(retrieved_account.wallet_id, updated_account.wallet_id);
    }
}
