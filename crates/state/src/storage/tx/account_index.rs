//! Helpers for accessing account index information in the database

use libmdbx::{RW, TransactionKind};
use types_account::account::{Account, OrderId};
use types_core::AccountId;
use util::res_some;

use crate::{
    INTENT_TO_WALLET_TABLE, WALLETS_TABLE, storage::ArchivedValue, storage::error::StorageError,
};

use super::StateTxn;

/// Type alias for an archived account value with transaction lifetime
pub type AccountValue<'a> = ArchivedValue<'a, Account>;

// -----------
// | Getters |
// -----------

impl<T: TransactionKind> StateTxn<'_, T> {
    /// Get the account associated with the given ID
    pub fn get_account(
        &self,
        account_id: &AccountId,
    ) -> Result<Option<AccountValue<'_>>, StorageError> {
        self.inner().read(WALLETS_TABLE, account_id)
    }

    /// Get the account ID managing a given order
    pub fn get_account_id_for_order(
        &self,
        intent_id: &OrderId,
    ) -> Result<Option<AccountId>, StorageError> {
        self.inner()
            .read::<_, OrderId>(INTENT_TO_WALLET_TABLE, intent_id)
            .map(|opt| opt.map(|archived| archived.deserialize()).transpose())?
    }

    /// Get the account for a given order
    pub fn get_account_for_order(
        &self,
        intent_id: &OrderId,
    ) -> Result<Option<AccountValue<'_>>, StorageError> {
        let account_id = res_some!(self.get_account_id_for_order(intent_id)?);
        self.get_account(&account_id)
    }

    /// Get all the accounts in the database
    pub fn get_all_accounts(&self) -> Result<Vec<AccountValue<'_>>, StorageError> {
        // Create a cursor and take only the values
        let account_cursor = self.inner().cursor::<AccountId, Account>(WALLETS_TABLE)?.into_iter();
        let accounts = account_cursor.values().collect::<Result<Vec<_>, _>>()?;

        Ok(accounts)
    }
}

// -----------
// | Setters |
// -----------

impl StateTxn<'_, RW> {
    /// Write an account to the table
    pub fn write_account(&self, account: &Account) -> Result<(), StorageError> {
        self.inner().write(WALLETS_TABLE, &account.id, account)
    }

    /// Update the mapping from order to account for each of the given orders
    pub fn index_orders(
        &self,
        account_id: &AccountId,
        orders: &[OrderId],
    ) -> Result<(), StorageError> {
        for order in orders.iter() {
            self.inner().write(INTENT_TO_WALLET_TABLE, order, account_id)?;
        }

        Ok(())
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    use types_account::{account::OrderId, mocks::mock_empty_account};
    use types_core::AccountId;

    use crate::{INTENT_TO_WALLET_TABLE, WALLETS_TABLE, test_helpers::mock_db};
    use itertools::Itertools;

    /// Tests adding an account then retrieving it
    #[test]
    fn test_add_account() {
        let db = mock_db();
        db.create_table(WALLETS_TABLE).unwrap();

        // Write the account
        let account = mock_empty_account();
        let tx = db.new_write_tx().unwrap();
        tx.write_account(&account).unwrap();
        tx.commit().unwrap();

        // Read the account
        let tx = db.new_read_tx().unwrap();
        let account_res = tx.get_account(&account.id).unwrap();
        assert!(account_res.is_some());
        let retrieved = account_res.unwrap().deserialize().unwrap();
        assert_eq!(retrieved.id, account.id);
    }

    /// Tests adding an account for an order then retrieving it
    #[test]
    fn test_get_account_id_for_intent() {
        let db = mock_db();
        db.create_table(INTENT_TO_WALLET_TABLE).unwrap();

        // Write the mapping
        let intent_id1 = OrderId::new_v4();
        let intent_id2 = OrderId::new_v4();
        let intent_id3 = OrderId::new_v4();
        let account_id1 = AccountId::new_v4();
        let account_id2 = AccountId::new_v4();

        let tx = db.new_write_tx().unwrap();
        tx.index_orders(&account_id1, &[intent_id1, intent_id2]).unwrap();
        tx.index_orders(&account_id2, &[intent_id3]).unwrap();
        tx.commit().unwrap();

        // Check all order mappings
        let tx = db.new_read_tx().unwrap();
        let account_res1 = tx.get_account_id_for_order(&intent_id1).unwrap();
        assert_eq!(account_res1, Some(account_id1));
        let account_res2 = tx.get_account_id_for_order(&intent_id2).unwrap();
        assert_eq!(account_res2, Some(account_id1));
        let account_res3 = tx.get_account_id_for_order(&intent_id3).unwrap();
        assert_eq!(account_res3, Some(account_id2));
    }

    /// Tests creating multiple accounts and retrieving them all
    #[test]
    fn test_get_all_accounts() {
        let db = mock_db();
        db.create_table(WALLETS_TABLE).unwrap();

        const N: usize = 10;
        let mut accounts = (0..N).map(|_| mock_empty_account()).collect_vec();
        let tx = db.new_write_tx().unwrap();
        for account in accounts.iter() {
            tx.write_account(account).unwrap();
        }
        tx.commit().unwrap();

        // Read the accounts
        let tx = db.new_read_tx().unwrap();
        let accounts_res = tx.get_all_accounts().unwrap();
        assert_eq!(accounts_res.len(), N);

        // Deserialize and sort for comparison
        let mut deserialized: Vec<_> =
            accounts_res.into_iter().map(|archived| archived.deserialize().unwrap()).collect();
        deserialized.sort_by_key(|account| account.id);
        accounts.sort_by_key(|account| account.id);
        assert_eq!(deserialized, accounts);
    }
}
