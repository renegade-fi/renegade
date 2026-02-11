//! Applicator methods for the account index, separated out for discoverability

use std::collections::HashSet;

use alloy::sol_types::SolValue;
use alloy_primitives::{Address, keccak256};
use matching_engine_core::MatchingEngine;
use renegade_solidity_abi::v2::IDarkpoolV2::PublicIntentPermit;
use system_bus::{
    ADMIN_BALANCE_UPDATES_TOPIC, ADMIN_ORDER_UPDATES_TOPIC, AdminOrderUpdateType,
    OWNER_INDEX_CHANGED_TOPIC, SystemBusMessage,
};
use types_account::{
    MatchingPoolName, OrderRefreshData,
    account::{Account, OrderId},
    balance::Balance,
    keychain::KeyChain,
    order::Order,
    order_auth::OrderAuth,
};
use types_core::AccountId;
use types_proofs::ValidityProofLocator;

use crate::{
    applicator::error::StateApplicatorError,
    storage::{traits::RkyvValue, tx::StateTxn},
};

use super::{Result, StateApplicator, return_type::ApplicatorReturnType};

/// Update the matching engine cache for orders affected by a balance change
pub fn update_matchable_amounts<T: libmdbx::TransactionKind>(
    account_id: AccountId,
    balance: &Balance,
    engine: &MatchingEngine,
    tx: &StateTxn<'_, T>,
) -> Result<()> {
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
            engine.upsert_order(account_id, &order, matchable_amount, matching_pool);
        } else {
            engine.cancel_order(&order, matching_pool);
        }
    }
    Ok(())
}

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
        pool: MatchingPoolName,
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

        // Assign the order to the specified matching pool
        tx.assign_order_to_matching_pool(&order.id, &pool)?;

        // Index the intent hash for on-chain event correlation
        if let OrderAuth::PublicOrder { permit, .. } = auth {
            let intent_hash = keccak256(permit.abi_encode());
            tx.set_intent_to_order_and_account(&intent_hash, &account_id, &order.id)?;
        };

        // Index the owner for balance event routing
        // TODO: When multiple rings are enabled, only index Ring 0/1 orders
        let owner = order.intent().owner;
        let is_new_entry = tx.get_account_by_owner(&owner)?.is_none();
        tx.set_owner_to_account(&owner, &account_id)?;

        // Get the matchable amount for matching engine updates
        let matchable_amount = tx.get_order_matchable_amount(&order.id)?.unwrap_or_default();
        tx.commit()?;

        // Notify chain-events worker to refresh subscriptions if new owner
        if is_new_entry {
            self.publish_owner_index_changed(owner, true /* added */);
        }

        // Update the matching engine book
        if matchable_amount > 0 {
            let engine = self.matching_engine();
            engine.upsert_order(account_id, order, matchable_amount, pool.clone());
        }

        // Publish admin order update event
        self.publish_admin_order_update(account_id, order, pool, AdminOrderUpdateType::Created);
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
        let pool = tx.get_matching_pool_for_order(&order_id)?;

        // Delete the intent hash index
        let executor = tx.get_executor_key()?.address();
        let permit = PublicIntentPermit { intent: order.intent().clone().into(), executor };
        let intent_hash = keccak256(permit.abi_encode());
        tx.remove_intent_mapping(&intent_hash)?;

        // Remove order from account storage
        tx.remove_order_with_auth(&account_id, &order_id)?;

        // Remove all validity proofs keyed by this order
        let locator = ValidityProofLocator::Intent { order_id };
        tx.delete_all_validity_proofs(&locator)?;

        // Clean up owner index if account has no remaining orders
        let owner = order.intent().owner;
        let should_remove_owner = tx.get_account_orders(&account_id)?.is_empty();
        if should_remove_owner {
            tx.remove_owner_mapping(&owner)?;
        }

        tx.commit()?;

        // Notify chain-events worker if owner index was deleted
        if should_remove_owner {
            self.publish_owner_index_changed(owner, false /* added */);
        }

        // Remove from the matching engine
        self.matching_engine().cancel_order(&order, pool.clone());

        // Publish admin order update event
        self.publish_admin_order_update(account_id, &order, pool, AdminOrderUpdateType::Cancelled);
        Ok(ApplicatorReturnType::None)
    }

    /// Update an existing order
    pub fn update_order(&self, order: &Order) -> Result<ApplicatorReturnType> {
        let tx = self.db().new_write_tx()?;

        // Verify the order exists
        let order_id = order.id;
        if tx.get_order(&order_id)?.is_none() {
            return Err(StateApplicatorError::reject(format!("order {order_id} not found")));
        }

        // Get the account ID for the order
        let account_id = tx
            .get_account_id_for_order(&order_id)?
            .ok_or_else(|| StateApplicatorError::reject("order not associated with account"))?;

        // Update the order in storage
        tx.update_order(&account_id, order)?;

        // Get the info needed to update the matching engine
        let pool = tx.get_matching_pool_for_order(&order_id)?;
        let matchable_amount = tx.get_order_matchable_amount(&order_id)?.unwrap_or_default();
        tx.commit()?;

        // Update the matching engine book
        if matchable_amount > 0 {
            self.matching_engine().upsert_order(account_id, order, matchable_amount, pool.clone());
        } else {
            self.matching_engine().cancel_order(order, pool.clone());
        }

        // Publish admin order update event
        self.publish_admin_order_update(account_id, order, pool, AdminOrderUpdateType::Updated);
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

        // Remove balance validity proofs if the darkpool balance is zeroed
        if balance.location.is_darkpool() && balance.amount() == 0 {
            let locator = ValidityProofLocator::Balance { account_id, mint: balance.mint() };
            tx.delete_all_validity_proofs(&locator)?;
        }

        tx.commit()?;

        // Open a read transaction to get order info for matching engine updates
        // We do this after committing to ensure the balance state is durable
        let engine = self.matching_engine();
        let tx = self.db().new_read_tx()?;
        update_matchable_amounts(account_id, balance, &engine, &tx)?;

        // Publish admin balance update event
        self.publish_admin_balance_update(account_id, balance);
        Ok(ApplicatorReturnType::None)
    }

    /// Update an account's keychain
    pub fn update_account_keychain(
        &self,
        account_id: AccountId,
        keychain: &KeyChain,
    ) -> Result<ApplicatorReturnType> {
        let tx = self.db().new_write_tx()?;
        if !tx.contains_account(&account_id)? {
            return Err(StateApplicatorError::reject("account not found"));
        }
        tx.update_keychain(&account_id, keychain)?;
        tx.commit()?;
        Ok(ApplicatorReturnType::None)
    }

    /// Refresh an account's state from the indexer
    pub fn refresh_account(
        &self,
        account_id: AccountId,
        orders: Vec<OrderRefreshData>,
        balances: &[Balance],
    ) -> Result<ApplicatorReturnType> {
        // Create write transaction
        let tx = self.db().new_write_tx()?;
        if !tx.contains_account(&account_id)? {
            return Err(StateApplicatorError::reject("account not found"));
        }

        // Update all balances
        for balance in balances {
            tx.update_balance(&account_id, balance)?;
            self.publish_admin_balance_update(account_id, balance);
        }

        // Collect order IDs from the refresh set
        let refresh_order_ids: HashSet<OrderId> = orders.iter().map(|o| o.order.id).collect();

        // Get current orders and identify stale ones to remove
        let current_orders = tx.get_account_orders(&account_id)?;
        let mut stale_orders = Vec::new();
        for order in current_orders {
            if !refresh_order_ids.contains(&order.id) {
                let matching_pool = tx.get_matching_pool_for_order(&order.id)?;
                tx.remove_order_with_auth(&account_id, &order.id)?;
                stale_orders.push((order, matching_pool));
            }
        }

        // Update all orders, their auth, and matching pool assignments
        // Track which orders are new vs updated
        for OrderRefreshData { order, matching_pool, auth } in &orders {
            // Check if the order exists
            let order_exists = tx.get_order(&order.id)?.is_some();

            let pool = matching_pool.clone();
            if order_exists {
                tx.update_order(&account_id, order)?;
                self.publish_admin_order_update(
                    account_id,
                    order,
                    pool,
                    AdminOrderUpdateType::Updated,
                );
            } else {
                tx.add_order(&account_id, order)?;
                self.publish_admin_order_update(
                    account_id,
                    order,
                    pool,
                    AdminOrderUpdateType::Created,
                );
            }

            // Write the order auth
            tx.write_order_auth(&order.id, auth)?;

            // Assign to the matching pool
            tx.assign_order_to_matching_pool(&order.id, matching_pool)?;
        }

        tx.commit()?;

        // Open a read transaction for matching engine updates
        let engine = self.matching_engine();
        let tx = self.db().new_read_tx()?;

        // Cancel stale orders in the matching engine and publish cancellation events
        for (order, matching_pool) in stale_orders {
            engine.cancel_order(&order, matching_pool.clone());
            self.publish_admin_order_update(
                account_id,
                &order,
                matching_pool,
                AdminOrderUpdateType::Cancelled,
            );
        }

        // Update/cancel refreshed orders based on matchable amount
        for OrderRefreshData { order, matching_pool, .. } in orders {
            let order_id = order.id;
            let matchable_amount = tx.get_order_matchable_amount(&order_id)?.unwrap_or_default();

            if matchable_amount > 0 {
                engine.upsert_order(account_id, &order, matchable_amount, matching_pool);
            } else {
                engine.cancel_order(&order, matching_pool);
            }
        }

        Ok(ApplicatorReturnType::None)
    }

    // -----------
    // | Helpers |
    // -----------

    /// Publish an admin order update event to the system bus
    fn publish_admin_order_update(
        &self,
        account_id: AccountId,
        order: &Order,
        matching_pool: String,
        update_type: AdminOrderUpdateType,
    ) {
        let msg = SystemBusMessage::AdminOrderUpdate {
            account_id,
            order: Box::new(order.clone()),
            matching_pool,
            update_type,
        };
        self.system_bus().publish(ADMIN_ORDER_UPDATES_TOPIC.to_string(), msg);
    }

    /// Publish an admin balance update event to the system bus
    fn publish_admin_balance_update(&self, account_id: AccountId, balance: &Balance) {
        let msg =
            SystemBusMessage::AdminBalanceUpdate { account_id, balance: Box::new(balance.clone()) };
        self.system_bus().publish(ADMIN_BALANCE_UPDATES_TOPIC.to_string(), msg);
    }

    /// Notify the chain-events worker that the owner index changed
    fn publish_owner_index_changed(&self, owner: Address, added: bool) {
        self.system_bus().publish(
            OWNER_INDEX_CHANGED_TOPIC.to_string(),
            SystemBusMessage::OwnerIndexChanged { owner, added },
        );
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
pub(crate) mod test {
    use alloy_primitives::Address;
    use circuit_types::Amount;
    use constants::GLOBAL_MATCHING_POOL;
    use types_account::{
        account::mocks::mock_empty_account,
        balance::mocks::mock_balance,
        order::mocks::{mock_order, mock_order_with_pair},
        order_auth::mocks::mock_order_auth,
        pair::Pair,
    };
    use types_proofs::{
        IntentOnlyValidityBundle, ValidityProofLocator, mocks::mock_intent_only_validity_bundle,
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
        applicator
            .add_order_to_account(account.id, &order, &auth, GLOBAL_MATCHING_POOL.to_string())
            .unwrap();

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
        applicator
            .add_order_to_account(account.id, &order, &auth, GLOBAL_MATCHING_POOL.to_string())
            .unwrap();

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
        applicator
            .add_order_to_account(account.id, &order, &auth, GLOBAL_MATCHING_POOL.to_string())
            .unwrap();

        // Add an intent-located validity proof for the order
        let locator = ValidityProofLocator::Intent { order_id: order.id };
        let proof_bundle = mock_intent_only_validity_bundle();
        let tx = applicator.db().new_write_tx().unwrap();
        tx.write_validity_proof::<IntentOnlyValidityBundle>(&locator, &proof_bundle).unwrap();
        tx.commit().unwrap();

        // Verify the order exists before removal
        let tx = applicator.db().new_read_tx().unwrap();
        let retrieved_account = tx.get_account(&account.id).unwrap().unwrap();
        assert!(retrieved_account.orders.contains_key(&order.id));
        assert!(tx.get_order(&order.id).unwrap().is_some());
        assert!(tx.get_order_auth(&order.id).unwrap().is_some());
        let matching_pool = tx.get_matching_pool_for_order(&order.id).unwrap();
        let contains_order = matching_engine.contains_order(&order, matching_pool.clone());
        assert!(contains_order);
        assert!(tx.get_validity_proof::<IntentOnlyValidityBundle>(&locator).unwrap().is_some());
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
        assert!(tx.get_validity_proof::<IntentOnlyValidityBundle>(&locator).unwrap().is_none());

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
        applicator
            .add_order_to_account(account.id, &order1, &auth, GLOBAL_MATCHING_POOL.to_string())
            .unwrap();
        applicator
            .add_order_to_account(account.id, &order2, &auth, GLOBAL_MATCHING_POOL.to_string())
            .unwrap();
        applicator
            .add_order_to_account(account.id, &order3, &auth, GLOBAL_MATCHING_POOL.to_string())
            .unwrap();

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
        let retrieved_balance = retrieved_account.get_eoa_balance(&mint).unwrap();
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

    // --- Owner Index Cleanup Tests ---

    /// Test that owner index is deleted when the last order for an owner is
    /// removed
    #[test]
    fn test_owner_index_cleanup_on_last_order_removal() {
        let applicator = mock_applicator();

        // Add an account
        let account = mock_empty_account();
        applicator.create_account(&account).unwrap();

        // Add an order
        let order = mock_order();
        let auth = mock_order_auth();
        let owner = order.intent().owner;
        applicator
            .add_order_to_account(account.id, &order, &auth, GLOBAL_MATCHING_POOL.to_string())
            .unwrap();

        // Verify owner index was created
        let tx = applicator.db().new_read_tx().unwrap();
        assert_eq!(tx.get_account_by_owner(&owner).unwrap(), Some(account.id));
        drop(tx);

        // Remove the order
        applicator.remove_order_from_account(account.id, order.id).unwrap();

        // Verify owner index was deleted
        let tx = applicator.db().new_read_tx().unwrap();
        assert_eq!(tx.get_account_by_owner(&owner).unwrap(), None);
    }

    /// Test that owner index is retained when another order for the same owner
    /// remains
    #[test]
    fn test_owner_index_retained_with_remaining_order() {
        let applicator = mock_applicator();

        // Add an account
        let account = mock_empty_account();
        applicator.create_account(&account).unwrap();

        // Add two orders with the same owner
        let mut order1 = mock_order();
        let mut order2 = mock_order();
        let owner = Address::from([0xAA; 20]);
        order1.intent.inner.owner = owner;
        order2.intent.inner.owner = owner;
        let auth = mock_order_auth();

        applicator
            .add_order_to_account(account.id, &order1, &auth, GLOBAL_MATCHING_POOL.to_string())
            .unwrap();
        applicator
            .add_order_to_account(account.id, &order2, &auth, GLOBAL_MATCHING_POOL.to_string())
            .unwrap();

        // Verify owner index exists
        let tx = applicator.db().new_read_tx().unwrap();
        assert_eq!(tx.get_account_by_owner(&owner).unwrap(), Some(account.id));
        drop(tx);

        // Remove one order
        applicator.remove_order_from_account(account.id, order1.id).unwrap();

        // Verify owner index is still present (order2 remains)
        let tx = applicator.db().new_read_tx().unwrap();
        assert_eq!(tx.get_account_by_owner(&owner).unwrap(), Some(account.id));
        drop(tx);

        // Remove the second order
        applicator.remove_order_from_account(account.id, order2.id).unwrap();

        // Now owner index should be deleted
        let tx = applicator.db().new_read_tx().unwrap();
        assert_eq!(tx.get_account_by_owner(&owner).unwrap(), None);
    }
}
