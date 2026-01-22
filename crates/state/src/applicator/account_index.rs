//! Applicator methods for the account index, separated out for discoverability

use job_types::matching_engine::MatchingEngineWorkerJob;
use tracing::warn;
use types_account::{
    account::{Account, OrderId},
    balance::Balance,
    order::Order,
    order_auth::OrderAuth,
};
use types_core::AccountId;

use crate::{applicator::error::StateApplicatorError, storage::traits::RkyvValue};

use super::{Result, StateApplicator, return_type::ApplicatorReturnType};

impl StateApplicator {
    // -------------
    // | Interface |
    // -------------

    /// Create a new account
    pub fn create_account(&self, account: &Account) -> Result<ApplicatorReturnType> {
        if !account.orders.is_empty() || !account.balances.is_empty() {
            return Err(StateApplicatorError::reject("cannot create a non-empty account"));
        }

        // Add the account to the account indices
        let tx = self.db().new_write_tx()?;

        // Write the account (new accounts are empty, so no intents to index)
        tx.new_account(account)?;
        tx.commit()?;
        Ok(ApplicatorReturnType::None)
    }

    /// Add an order to an account
    pub fn add_order_to_account(
        &self,
        account_id: AccountId,
        order: &Order,
        auth: &OrderAuth,
    ) -> Result<ApplicatorReturnType> {
        // Create write transaction
        let tx = self.db().new_write_tx()?;

        // Verify account exists
        if !tx.contains_account(&account_id)? {
            return Err(StateApplicatorError::reject("account not found"));
        }

        // Write the order fields
        tx.add_order(&account_id, order)?;
        tx.write_order_auth(&order.id, auth)?;

        // Get the info needed to update the matching engine
        let matching_pool = tx.get_matching_pool_for_order(&order.id)?;
        let matchable_amount = tx.get_order_matchable_amount(&order.id)?.unwrap_or_default();
        tx.commit()?;

        // Update the matching engine
        if matchable_amount > 0 {
            self.matching_engine().upsert_order(order, matchable_amount, matching_pool);
            self.run_matching_engine_on_order(&order.id);
        }
        Ok(ApplicatorReturnType::None)
    }

    /// Remove an order from an account
    pub fn remove_order_from_account(
        &self,
        account_id: AccountId,
        order_id: OrderId,
    ) -> Result<ApplicatorReturnType> {
        // Create write transaction
        let tx = self.db().new_write_tx()?;

        // Verify account exists
        if !tx.contains_account(&account_id)? {
            return Err(StateApplicatorError::reject("account not found"));
        }

        // Get the order and matching pool before removing
        let archived_order = tx
            .get_order(&order_id)?
            .ok_or_else(|| StateApplicatorError::reject(format!("order {order_id} not found")))?;
        let order = Order::from_archived(&archived_order)?;
        let matching_pool = tx.get_matching_pool_for_order(&order_id)?;

        // Remove order from account storage
        tx.remove_order(&account_id, &order_id)?;
        tx.delete_order_auth(&order_id)?;
        tx.remove_order_from_matching_pool(&order_id)?;
        tx.commit()?;

        // Remove from the matching engine
        self.matching_engine().cancel_order(&order, matching_pool);
        Ok(ApplicatorReturnType::None)
    }

    /// Update a balance in an account
    pub fn update_account_balance(
        &self,
        account_id: AccountId,
        balance: &Balance,
    ) -> Result<ApplicatorReturnType> {
        // Create write transaction
        let tx = self.db().new_write_tx()?;
        if !tx.contains_account(&account_id)? {
            return Err(StateApplicatorError::reject("account not found"));
        }
        tx.update_balance(&account_id, balance)?;
        tx.commit()?;

        // Open a read transaction to get order info for matching engine updates
        // We do this after committing to ensure the balance state is durable
        let engine = self.matching_engine();
        let tx = self.db().new_read_tx()?;

        let affected_order_ids = tx.get_orders_with_input_token(&account_id, &balance.mint())?;
        for order_id in affected_order_ids {
            let order = match tx.get_order(&order_id)? {
                Some(archived_order) => Order::from_archived(&archived_order)?,
                None => {
                    tracing::warn!("order {order_id} not found, skipping matchable amount update");
                    continue;
                },
            };

            // Fetch the information the matching engine needs to update
            let matching_pool = tx.get_matching_pool_for_order(&order_id)?;
            let matchable_amount = tx.get_order_matchable_amount(&order_id)?.unwrap_or_default();
            if matchable_amount > 0 {
                engine.upsert_order(&order, matchable_amount, matching_pool);
                self.run_matching_engine_on_order(&order_id);
            } else {
                engine.cancel_order(&order, matching_pool);
            }
        }

        Ok(ApplicatorReturnType::None)
    }

    // --- Helpers --- //

    /// Run the matching engine on an order
    fn run_matching_engine_on_order(&self, id: &OrderId) {
        let job = MatchingEngineWorkerJob::run_internal_engine(*id);
        if let Err(e) = self.config.matching_engine_worker_queue.send(job) {
            warn!("Error enqueuing matching engine job for order {id}: {e}");
        }
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
pub(crate) mod test {
    use alloy_primitives::Address;
    use circuit_types::Amount;
    use types_account::{
        account::mocks::mock_empty_account,
        balance::mocks::mock_balance,
        order::mocks::{mock_order, mock_order_with_pair},
        order_auth::mocks::mock_order_auth,
        pair::Pair,
    };

    use crate::applicator::test_helpers::mock_applicator;

    /// Tests adding a new account to the index
    #[test]
    fn test_create_account() {
        let applicator = mock_applicator();

        // Add an account
        let account = mock_empty_account();
        applicator.create_account(&account).unwrap();

        // Check that the account exists
        let tx = applicator.db().new_read_tx().unwrap();
        let retrieved_account = tx.get_account(&account.id).unwrap();
        assert!(retrieved_account.is_some());
        let retrieved_account = retrieved_account.unwrap();
        assert_eq!(retrieved_account.id, account.id);
    }

    /// Test adding an order to an account
    #[test]
    #[allow(non_snake_case)]
    fn test_add_order_to_account__no_balance() {
        let applicator = mock_applicator();

        // Add an account
        let account = mock_empty_account();
        applicator.create_account(&account).unwrap();

        // Add an order to the account
        let order = mock_order();
        let auth = mock_order_auth();
        applicator.add_order_to_account(account.id, &order, &auth).unwrap();

        // Check that the order is stored in the account
        let tx = applicator.db().new_read_tx().unwrap();
        let retrieved_account = tx.get_account(&account.id).unwrap().unwrap();
        assert!(retrieved_account.orders.contains_key(&order.id));

        // Check the order -> account mapping
        let account_id = tx.get_account_id_for_order(&order.id).unwrap();
        assert_eq!(account_id, Some(account.id));

        // Check that the order can be retrieved
        let retrieved_order = tx.get_order(&order.id).unwrap();
        assert!(retrieved_order.is_some());
        let retrieved_order = retrieved_order.unwrap().deserialize().unwrap();
        assert_eq!(retrieved_order.id, order.id);

        // Check that the order auth is stored
        let retrieved_auth = tx.get_order_auth(&order.id).unwrap();
        assert!(retrieved_auth.is_some());
        let retrieved_auth = retrieved_auth.unwrap().deserialize().unwrap();
        assert_eq!(retrieved_auth, auth);

        // Check that the order is not in the matching engine
        let matching_pool = tx.get_matching_pool_for_order(&order.id).unwrap();
        let contains_order = applicator.matching_engine().contains_order(&order, matching_pool);
        assert!(!contains_order); // zero matchable amount, so not in the matching engine
    }

    /// Test adding an order to an account with a balance
    #[test]
    #[allow(non_snake_case)]
    fn test_add_order_to_account__with_balance() {
        let applicator = mock_applicator();
        let order = mock_order();
        let auth = mock_order_auth();
        let mut balance = mock_balance();
        balance.state_wrapper.inner.mint = order.input_token();

        // Add an account
        let account = mock_empty_account();
        applicator.create_account(&account).unwrap();

        // Add a balance, then an order
        applicator.update_account_balance(account.id, &balance).unwrap();
        applicator.add_order_to_account(account.id, &order, &auth).unwrap();

        // Check that the order is stored in the account
        let tx = applicator.db().new_read_tx().unwrap();
        let retrieved_account = tx.get_account(&account.id).unwrap().unwrap();
        assert!(retrieved_account.orders.contains_key(&order.id));

        // Check that the order is in the matching engine
        let matching_pool = tx.get_matching_pool_for_order(&order.id).unwrap();
        let contains_order = applicator.matching_engine().contains_order(&order, matching_pool);
        assert!(contains_order);
    }

    /// Test removing an order from an account
    #[test]
    fn test_remove_order_from_account() {
        let applicator = mock_applicator();
        let order = mock_order();
        let auth = mock_order_auth();
        let mut balance = mock_balance();
        balance.state_wrapper.inner.mint = order.input_token();
        let matching_engine = applicator.matching_engine().clone();

        // Add an account
        let account = mock_empty_account();
        applicator.create_account(&account).unwrap();

        // Add a balance, then an order
        applicator.update_account_balance(account.id, &balance).unwrap();
        applicator.add_order_to_account(account.id, &order, &auth).unwrap();

        // Verify the order exists before removal
        let tx = applicator.db().new_read_tx().unwrap();
        let retrieved_account = tx.get_account(&account.id).unwrap().unwrap();
        assert!(retrieved_account.orders.contains_key(&order.id));
        assert!(tx.get_order(&order.id).unwrap().is_some());
        assert!(tx.get_order_auth(&order.id).unwrap().is_some());
        let matching_pool = tx.get_matching_pool_for_order(&order.id).unwrap();
        let contains_order = matching_engine.contains_order(&order, matching_pool.clone());
        assert!(contains_order);
        drop(tx);

        // Remove the order from the account
        applicator.remove_order_from_account(account.id, order.id).unwrap();

        // Verify the order is removed from the account
        let tx = applicator.db().new_read_tx().unwrap();
        let retrieved_account = tx.get_account(&account.id).unwrap().unwrap();
        assert!(!retrieved_account.orders.contains_key(&order.id));

        // Verify the order -> account mapping is removed
        let account_id = tx.get_account_id_for_order(&order.id).unwrap();
        assert_eq!(account_id, None);

        // Verify the order cannot be retrieved
        assert!(tx.get_order(&order.id).unwrap().is_none());
        assert!(tx.get_order_auth(&order.id).unwrap().is_none());

        // Verify the order is removed from the matching engine
        let matching_pool = tx.get_matching_pool_for_order(&order.id).unwrap();
        let contains_order = matching_engine.contains_order(&order, matching_pool.clone());
        assert!(!contains_order);
    }

    /// Test updating an account balance
    #[test]
    fn test_update_account_balance() {
        let applicator = mock_applicator();
        let matching_engine = applicator.matching_engine().clone();

        // Add an account
        let account = mock_empty_account();
        applicator.create_account(&account).unwrap();

        // Create a balance
        let mut balance = mock_balance();
        let mint = balance.mint();

        // Create orders with different input tokens
        let mint1 = Address::from([1u8; 20]);
        let mint2 = Address::from([2u8; 20]);
        let pair1 = Pair::new(mint, mint1); // Uses balance mint as input
        let pair2 = Pair::new(mint, mint2); // Uses balance mint as input
        let pair3 = Pair::new(mint1, mint); // Uses different mint as input

        let order1 = mock_order_with_pair(pair1);
        let order2 = mock_order_with_pair(pair2);
        let order3 = mock_order_with_pair(pair3);
        let auth = mock_order_auth();

        // Add orders to the account
        applicator.add_order_to_account(account.id, &order1, &auth).unwrap();
        applicator.add_order_to_account(account.id, &order2, &auth).unwrap();
        applicator.add_order_to_account(account.id, &order3, &auth).unwrap();

        // Verify initial matchable amounts
        let tx = applicator.db().new_read_tx().unwrap();
        let matching_pool1 = tx.get_matching_pool_for_order(&order1.id).unwrap();
        let matching_pool2 = tx.get_matching_pool_for_order(&order2.id).unwrap();
        let matching_pool3 = tx.get_matching_pool_for_order(&order3.id).unwrap();
        let initial_matchable1 = tx.get_order_matchable_amount(&order1.id).unwrap().unwrap();
        let initial_matchable2 = tx.get_order_matchable_amount(&order2.id).unwrap().unwrap();
        let initial_matchable3 = tx.get_order_matchable_amount(&order3.id).unwrap().unwrap();

        // Verify initial matchable amounts are all zero (no balance initially)
        assert_eq!(initial_matchable1, 0);
        assert_eq!(initial_matchable2, 0);
        assert_eq!(initial_matchable3, 0);
        drop(tx);

        // Update the balance (increase amount)
        const AMOUNT_ADDED: Amount = 1000;
        *balance.amount_mut() = AMOUNT_ADDED;
        applicator.update_account_balance(account.id, &balance).unwrap();

        // Verify balance was updated
        let tx = applicator.db().new_read_tx().unwrap();
        let retrieved_account = tx.get_account(&account.id).unwrap().unwrap();
        let retrieved_balance = retrieved_account.get_balance(&mint).unwrap();
        assert_eq!(retrieved_balance.amount(), AMOUNT_ADDED);

        // Verify orders using the updated balance's mint have updated matchable amounts
        let new_matchable1 = tx.get_order_matchable_amount(&order1.id).unwrap().unwrap();
        let new_matchable2 = tx.get_order_matchable_amount(&order2.id).unwrap().unwrap();
        let new_matchable3 = tx.get_order_matchable_amount(&order3.id).unwrap().unwrap();
        assert_eq!(new_matchable1, AMOUNT_ADDED);
        assert_eq!(new_matchable2, AMOUNT_ADDED);
        assert_eq!(new_matchable3, 0);

        // Verify matching engine matchable amounts match transaction layer values
        let engine_matchable1_after =
            matching_engine.get_matchable_amount(&order1, matching_pool1.clone()).unwrap();
        let engine_matchable2_after =
            matching_engine.get_matchable_amount(&order2, matching_pool2.clone()).unwrap();

        assert_eq!(engine_matchable1_after, new_matchable1);
        assert_eq!(engine_matchable2_after, new_matchable2);

        // Verify matching engine was updated for orders 1 and 2 (using balance mint)
        // Order 3 should not be affected since it uses a different input token
        assert!(matching_engine.contains_order(&order1, matching_pool1));
        assert!(matching_engine.contains_order(&order2, matching_pool2));
        assert!(!matching_engine.contains_order(&order3, matching_pool3));
    }
}
