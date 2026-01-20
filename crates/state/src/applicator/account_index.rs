//! Applicator methods for the account index, separated out for discoverability

use system_bus::{SystemBusMessage, account_topic};
use types_account::account::Account;

use crate::applicator::error::StateApplicatorError;

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

// #[cfg(test)]
// pub(crate) mod test {
//     use types_account::{
//         account::{Account, mocks::mock_empty_account},
//         order::mocks::mock_order,
//         order_auth::OrderAuth,
//     };
//     use types_core::AccountId;

//     use crate::{INTENT_TO_WALLET_TABLE, WALLETS_TABLE,
// applicator::test_helpers::mock_applicator};

//     /// Tests adding a new account to the index
//     #[test]
//     fn test_create_account() {
//         let applicator = mock_applicator();

//         // Add an account
//         let account = mock_empty_account();
//         applicator.create_account(&account).unwrap();

//         // Check that the account is indexed correctly
//         let expected_account: Account = account;

//         let db = applicator.db();
//         let account: Account = db.read(WALLETS_TABLE,
// &expected_account.id).unwrap().unwrap();

//         assert_eq!(account, expected_account);
//     }

//     /// Test adding a local order to an account
//     #[test]
//     fn test_add_local_order() {
//         let applicator = mock_applicator();

//         // Add an account
//         let account = mock_empty_account();
//         applicator.create_account(&account).unwrap();

//         // Add a local order to the account
//         let order = mock_order();
//         let auth = OrderAuth::PublicOrder {
//             intent_signature:
// renegade_solidity_abi::v2::IDarkpoolV2::SignatureWithNonce {
// nonce: alloy::primitives::U256::from(0),                 signature:
// alloy::primitives::Bytes::from(vec![0u8; 65]),             },
//         };
//         applicator.add_local_order(account.id, &order, &auth).unwrap();

//         // Check that the indexed account is as expected
//         let db = applicator.db();
//         let updated_account: Account = db.read(WALLETS_TABLE,
// &account.id).unwrap().unwrap();

//         assert_eq!(updated_account.id, account.id);
//         assert!(updated_account.orders.contains_key(&order.id));

//         // Check the intent -> account mapping
//         let order_id = updated_account.orders.keys().next().unwrap();
//         let account_id: AccountId = db.read(INTENT_TO_WALLET_TABLE,
// order_id).unwrap().unwrap();         assert_eq!(account_id, account.id);
//     }
// }
