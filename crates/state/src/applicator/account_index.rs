//! Applicator methods for the account index, separated out for discoverability

use system_bus::{SystemBusMessage, account_topic};
use types_account::{
    account::{Account, OrderId},
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

        // Publish a message to the bus describing the account update
        self.publish_account_update(account);
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
        self.matching_engine().add_order(order, matchable_amount, matching_pool);
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

    // /// Update an account in the state
    // ///
    // /// This update may take many forms: placing/cancelling an intent,
    // /// depositing or withdrawing a balance, etc.
    // ///
    // /// It is assumed that the update to the account is proven valid and posted
    // /// on-chain before this method is called. That is, we maintain the
    // /// invariant that the state stored by this module is valid -- but
    // /// possibly stale -- contract state
    // ///
    // /// NOTE: This method is kept for reference but is no longer used.
    // /// Use `add_local_order` instead for order updates.
    // ///
    // /// TODO: Delete this method
    // #[allow(dead_code)]
    // pub fn update_account(&self, account: &Account) ->
    // Result<ApplicatorReturnType> {     let tx = self.db().new_write_tx()?;

    //     // Index the intents in the account
    //     self.index_intents_with_tx(account, &tx)?;

    //     // Write the account
    //     // tx.write_account(account)?;
    //     tx.commit()?;

    //     // Push updates to the bus
    //     self.publish_account_update(account);
    //     self.system_bus().publish(
    //         ADMIN_WALLET_UPDATES_TOPIC.to_string(),
    //         SystemBusMessage::AdminAccountUpdate { account_id: account.id },
    //     );

    //     Ok(ApplicatorReturnType::None)
    // }

    // -----------
    // | Helpers |
    // -----------

    /// Publish an account update message to the system bus
    fn publish_account_update(&self, account: &Account) {
        let account_topic = account_topic(&account.id);
        self.system_bus().publish(
            account_topic,
            SystemBusMessage::AccountUpdate { account: Box::new(account.clone()) },
        );
    }

    // /// Index the intents of an account
    // fn index_intents_with_tx(&self, account: &Account, tx: &StateTxn<RW>) ->
    // Result<()> {     // Update the intent -> account mapping
    //     let nonzero_intents = account.orders.keys().copied().collect_vec();
    //     // tx.index_orders(&account.id, &nonzero_intents)?;

    //     // Handle cancelled intents
    //     self.handle_cancelled_intents(account, tx)
    // }

    // /// Handle cancelled intents
    // fn handle_cancelled_intents(&self, account: &Account, tx: &StateTxn<RW>) ->
    // Result<()> {     let old_account = tx.get_account(&account.id)?;
    //     let old_intents = old_account
    //         .map(|a|
    // a.deserialize().unwrap().orders.keys().copied().collect_vec())
    //         .unwrap_or_default();

    //     // Handle cancelled intents
    //     for id in old_intents {
    //         if !account.orders.contains_key(&id) {
    //             self.handle_cancelled_intent(id, tx)?;
    //         }
    //     }

    //     Ok(())
    // }

    // /// Handle a cancelled intent
    // fn handle_cancelled_intent(&self, id: OrderId, tx: &StateTxn<RW>) ->
    // Result<()> {     // Remove the order from the matching engine
    //     let matching_pool = tx.get_matching_pool_for_order(&id)?;
    //     let id = tx.get_account_id_for_order(&id)?.ok_or_else(||
    // reject_account_missing(id))?;     if let Some(order) =
    // account.get_order_deserialized(&id) {         self.matching_engine().
    // cancel_order(&order, matching_pool);     }

    //     // Remove the intent from its matching pool
    //     tx.remove_order_from_matching_pool(&id)?;

    //     // TODO: Remove the intent from the order book table
    //     // TODO: Delete proofs for the intent

    //     Ok(())
    // }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
pub(crate) mod test {
    use types_account::{
        account::mocks::mock_empty_account, order::mocks::mock_order,
        order_auth::mocks::mock_order_auth,
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
    fn test_add_order_to_account() {
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

        // Check that the order is in the matching engine
        let matching_pool = tx.get_matching_pool_for_order(&order.id).unwrap();
        assert!(applicator.matching_engine().contains_order(&order, matching_pool));
    }

    /// Test removing an order from an account
    #[test]
    fn test_remove_order_from_account() {
        let applicator = mock_applicator();
        let matching_engine = applicator.matching_engine().clone();

        // Add an account
        let account = mock_empty_account();
        applicator.create_account(&account).unwrap();

        // Add an order to the account
        let order = mock_order();
        let auth = mock_order_auth();
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
}
