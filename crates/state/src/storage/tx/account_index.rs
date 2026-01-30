//! Helpers for accessing account index information in the database
//!
//! This module implements a normalized storage model where:
//! - AccountHeader contains only id and keychain (small, stable)
//! - Orders are stored as separate KV entries
//! - Balances are stored as separate KV entries
//! - Order->account mapping is stored for quick order lookups

use alloy_primitives::{Address, B256};
use circuit_types::Amount;
use libmdbx::{RW, TransactionKind};
use serde::{Deserialize, Serialize};
use types_account::{
    account::{Account, OrderId},
    balance::{Balance, BalanceLocation},
    keychain::KeyChain,
    order::Order,
};
use types_core::AccountId;
use util::res_some;

use crate::{
    ACCOUNTS_TABLE,
    storage::{
        ArchivedValue,
        error::StorageError,
        traits::{RkyvValue, WithAddress},
    },
};

use super::StateTxn;

// ---------
// | Types |
// ---------

/// A lightweight account header containing only stable metadata
///
/// Orders and balances are stored separately and reconstructed on demand
#[derive(
    Clone,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug))]
pub struct AccountHeader {
    /// The account identifier
    pub id: AccountId,
    /// The keychain for the account
    pub keychain: KeyChain,
}

/// Type alias for an archived account header value with transaction lifetime
pub type AccountHeaderValue<'a> = ArchivedValue<'a, AccountHeader>;
/// Type alias for an archived order value with transaction lifetime
pub type OrderValue<'a> = ArchivedValue<'a, Order>;
/// Type alias for an archived balance value with transaction lifetime
pub type BalanceValue<'a> = ArchivedValue<'a, Balance>;

// -------------------
// | Key Helpers |
// -------------------

/// Build the key for an account header
fn account_header_key(account_id: &AccountId) -> String {
    format!("{account_id}:header")
}

/// Build the key for an order
fn order_key(account_id: &AccountId, order_id: &OrderId) -> String {
    format!("{account_id}:orders:{order_id}")
}

/// Build the prefix for scanning all orders of an account
fn orders_prefix(account_id: &AccountId) -> String {
    format!("{account_id}:orders:")
}

/// Build the key for a balance
fn balance_key(account_id: &AccountId, token: &Address, location: BalanceLocation) -> String {
    format!("{account_id}:balances:{location}:{token:?}")
}

/// Build the prefix for scanning all balances of an account
fn balances_prefix(account_id: &AccountId) -> String {
    format!("{account_id}:balances:")
}

/// Build the key for the order -> account index
fn order_index_key(order_id: &OrderId) -> String {
    format!("order_index:{order_id}")
}

/// Build the key for the owner -> account index
///
/// Maps (owner, token) to account_id for routing balance update events
fn owner_index_key(owner: &Address, token: &Address) -> String {
    format!("owner_index:{owner:?}:{token:?}")
}

/// Build the key for the intent hash -> order index
///
/// Maps intent_hash to (account_id, order_id) for routing public intent events
fn intent_hash_key(intent_hash: &B256) -> String {
    format!("intent_index:{intent_hash:?}")
}

// -----------
// | Getters |
// -----------

impl<T: TransactionKind> StateTxn<'_, T> {
    /// Whether the account exists
    pub fn contains_account(&self, account_id: &AccountId) -> Result<bool, StorageError> {
        self.get_account_header(account_id).map(|opt| opt.is_some())
    }

    /// Get the account header for the given ID
    pub fn get_account_header(
        &self,
        account_id: &AccountId,
    ) -> Result<Option<AccountHeaderValue<'_>>, StorageError> {
        let key = account_header_key(account_id);
        self.inner().read(ACCOUNTS_TABLE, &key)
    }

    /// Get the account ID managing a given order
    pub fn get_account_id_for_order(
        &self,
        order_id: &OrderId,
    ) -> Result<Option<AccountId>, StorageError> {
        let key = order_index_key(order_id);
        self.inner()
            .read::<_, AccountId>(ACCOUNTS_TABLE, &key)
            .map(|opt| opt.map(|archived| archived.deserialize()).transpose())?
    }

    /// Get an order by its ID
    ///
    /// Uses the order->account index to find the account, then retrieves the
    /// order
    pub fn get_order(&self, order_id: &OrderId) -> Result<Option<OrderValue<'_>>, StorageError> {
        let account_id = res_some!(self.get_account_id_for_order(order_id)?);
        let key = order_key(&account_id, order_id);
        self.inner().read(ACCOUNTS_TABLE, &key)
    }

    /// Get a balance for an account by token address
    pub fn get_balance(
        &self,
        account_id: &AccountId,
        token: &Address,
        location: BalanceLocation,
    ) -> Result<Option<BalanceValue<'_>>, StorageError> {
        let key = balance_key(account_id, token, location);
        self.inner().read(ACCOUNTS_TABLE, &key)
    }

    /// Get the order for a given order ID and the matchable amount
    ///
    /// The matchable amount is the minimum of the order's input amount and the
    /// account's balance for the order's input token
    pub fn get_order_matchable_amount(
        &self,
        order_id: &OrderId,
    ) -> Result<Option<Amount>, StorageError> {
        // Fetch the account and order
        let account = res_some!(self.get_account_id_for_order(order_id)?);
        let order = res_some!(self.get_order(order_id)?);
        let in_token = WithAddress::from_archived(order.input_token())?;

        // Fetch the capitalizing balance
        let location = BalanceLocation::from_archived(&order.ring.balance_location())?;
        let balance = match self.get_balance(&account, in_token.inner(), location)? {
            Some(balance) => balance,
            None => return Ok(Some(0)),
        };
        let bal_amt = balance.amount();

        let matchable_amount = Amount::min(bal_amt, order.amount_in());
        Ok(Some(matchable_amount))
    }

    /// Get order IDs for an account where the given mint is the input token
    ///
    /// This efficiently filters orders without deserializing full orders - only
    /// deserializes the input_token Address field for comparison.
    pub fn get_orders_with_input_token(
        &self,
        account_id: &AccountId,
        mint: &Address,
    ) -> Result<Vec<OrderId>, StorageError> {
        let order_prefix = orders_prefix(account_id);
        let order_cursor =
            self.inner().cursor::<String, Order>(ACCOUNTS_TABLE)?.with_key_prefix(&order_prefix);

        // Filter for orders with the given mint as input token
        let mut matching_order_ids = Vec::new();
        for (_, archived_order) in order_cursor.into_iter().filter_map(|res| res.ok()) {
            // Check the input token of the order
            let in_token = archived_order.input_token();

            // If input token matches, add to result
            if in_token == mint {
                let oid = archived_order.id;
                matching_order_ids.push(oid);
            }
        }

        Ok(matching_order_ids)
    }

    /// Get a full account by reconstructing from header, orders, and balances
    ///
    /// This method reads the account header, then scans all orders and balances
    /// for the account using prefix cursors
    pub fn get_account(&self, account_id: &AccountId) -> Result<Option<Account>, StorageError> {
        // Fetch the account header
        let header = res_some!(self.get_account_header(account_id)?).deserialize()?;

        // Fetch the orders and balances for the account
        let orders = self.fetch_orders_for_account(account_id)?;
        let balances = self.fetch_balances_for_account(account_id)?;

        // Reconstruct the account struct
        let account = Account::new(header.id, orders, balances, header.keychain);
        Ok(Some(account))
    }

    /// Get all account IDs in the database
    ///
    /// Iterates over all account headers and collects their IDs without
    /// reconstructing full accounts. This is more efficient when only the IDs
    /// are needed.
    pub fn get_all_account_ids(&self) -> Result<Vec<AccountId>, StorageError> {
        let header_cursor = self.inner().cursor::<String, AccountHeader>(ACCOUNTS_TABLE)?;
        let account_ids: Vec<AccountId> = header_cursor
            .into_iter()
            .filter_map(|res| {
                let (key, val) = res.ok()?;
                // Only process entries that are headers (keys ending with ":header")
                if key.ends_with(":header") {
                    let header = val.deserialize().ok()?;
                    Some(header.id)
                } else {
                    None
                }
            })
            .collect();

        Ok(account_ids)
    }

    /// Get all accounts in the database
    ///
    /// Iterates over all account headers, collects their IDs, and reconstructs
    /// each full account. Accounts for which reconstruction fails are filtered
    /// out.
    pub fn get_all_accounts(&self) -> Result<Vec<Account>, StorageError> {
        let account_ids = self.get_all_account_ids()?;

        // Call get_account for each account ID and filter out None results
        let mut accounts = Vec::new();
        for account_id in account_ids {
            if let Some(account) = self.get_account(&account_id)? {
                accounts.push(account);
            }
        }
        Ok(accounts)
    }

    /// Get all orders for an account without deserializing the full account
    pub fn get_account_orders(&self, account_id: &AccountId) -> Result<Vec<Order>, StorageError> {
        self.fetch_orders_for_account(account_id)
    }

    /// Get all balances for an account without deserializing the full account
    pub fn get_account_balances(
        &self,
        account_id: &AccountId,
    ) -> Result<Vec<Balance>, StorageError> {
        self.fetch_balances_for_account(account_id)
    }

    // --- Private Helpers --- //

    /// Fetch all orders for an account
    fn fetch_orders_for_account(&self, account_id: &AccountId) -> Result<Vec<Order>, StorageError> {
        let order_prefix = orders_prefix(account_id);
        let order_cursor =
            self.inner().cursor::<String, Order>(ACCOUNTS_TABLE)?.with_key_prefix(&order_prefix);
        order_cursor
            .into_iter()
            .map(|res| {
                let (_key, val) = res?;
                let order = val.deserialize()?;
                Ok(order)
            })
            .collect::<Result<_, StorageError>>()
    }

    /// Fetch all balances for an account
    fn fetch_balances_for_account(
        &self,
        account_id: &AccountId,
    ) -> Result<Vec<Balance>, StorageError> {
        let balance_prefix = balances_prefix(account_id);
        let balance_cursor = self
            .inner()
            .cursor::<String, Balance>(ACCOUNTS_TABLE)?
            .with_key_prefix(&balance_prefix);
        balance_cursor
            .into_iter()
            .map(|res| {
                let (_key, val) = res?;
                let balance = val.deserialize()?;
                Ok(balance)
            })
            .collect::<Result<_, StorageError>>()
    }

    /// Get the account ID for a given owner address and token
    ///
    /// Used to route balance update events to the correct account
    pub fn get_account_for_owner(
        &self,
        owner: &Address,
        token: &Address,
    ) -> Result<Option<AccountId>, StorageError> {
        let key = owner_index_key(owner, token);
        self.inner()
            .read::<_, AccountId>(ACCOUNTS_TABLE, &key)
            .map(|opt| opt.map(|archived| archived.deserialize()).transpose())?
    }

    /// Get all owner index entries
    ///
    /// Returns all (owner, token, account_id) tuples for state-based sync
    pub fn get_all_owner_index_entries(
        &self,
    ) -> Result<Vec<(Address, Address, AccountId)>, StorageError> {
        let prefix = "owner_index:";
        let cursor =
            self.inner().cursor::<String, AccountId>(ACCOUNTS_TABLE)?.with_key_prefix(prefix);

        cursor
            .into_iter()
            .filter_map(|res| {
                let (key, val) = res.ok()?;
                // Parse key format: "owner_index:{owner:?}:{token:?}"
                let parts: Vec<&str> = key.splitn(3, ':').collect();
                if parts.len() != 3 {
                    return None;
                }
                let owner = parts[1].parse::<Address>().ok()?;
                let token = parts[2].parse::<Address>().ok()?;
                let account_id = val.deserialize().ok()?;
                Some(Ok((owner, token, account_id)))
            })
            .collect()
    }

    /// Get the order for a given intent hash
    ///
    /// Used to route public intent events to the correct order
    pub fn get_order_for_intent_hash(
        &self,
        intent_hash: &B256,
    ) -> Result<Option<(AccountId, OrderId)>, StorageError> {
        let key = intent_hash_key(intent_hash);
        self.inner()
            .read::<_, (AccountId, OrderId)>(ACCOUNTS_TABLE, &key)
            .map(|opt| opt.map(|archived| archived.deserialize()).transpose())?
    }
}

// -----------
// | Setters |
// -----------

impl StateTxn<'_, RW> {
    /// Create a new account with only a header (no orders or balances)
    pub fn new_account(&self, account: &Account) -> Result<(), StorageError> {
        let header = AccountHeader { id: account.id, keychain: account.keychain.clone() };
        let key = account_header_key(&account.id);
        self.inner().write(ACCOUNTS_TABLE, &key, &header)
    }

    /// Add an order to an account
    ///
    /// This writes both the order data and the order->account index
    pub fn add_order(&self, account_id: &AccountId, order: &Order) -> Result<(), StorageError> {
        // Write the order
        let key = order_key(account_id, &order.id);
        self.inner().write(ACCOUNTS_TABLE, &key, order)?;

        // Write the order -> account index
        let index_key = order_index_key(&order.id);
        self.inner().write(ACCOUNTS_TABLE, &index_key, account_id)
    }

    /// Update an existing order in an account
    ///
    /// This only updates the order data, not the order->account index
    pub fn update_order(&self, account_id: &AccountId, order: &Order) -> Result<(), StorageError> {
        let key = order_key(account_id, &order.id);
        self.inner().write(ACCOUNTS_TABLE, &key, order)
    }

    /// Update (add or modify) a balance for an account
    pub fn update_balance(
        &self,
        account_id: &AccountId,
        balance: &Balance,
    ) -> Result<(), StorageError> {
        let location = balance.location;
        let key = balance_key(account_id, &balance.mint(), location);
        self.inner().write(ACCOUNTS_TABLE, &key, balance)
    }

    /// Remove an order from an account
    ///
    /// This deletes both the order data and the order->account index
    pub fn remove_order(
        &self,
        account_id: &AccountId,
        order_id: &OrderId,
    ) -> Result<(), StorageError> {
        // Delete the order
        let key = order_key(account_id, order_id);
        self.inner().delete(ACCOUNTS_TABLE, &key)?;

        // Delete the order -> account index
        let index_key = order_index_key(order_id);
        self.inner().delete(ACCOUNTS_TABLE, &index_key)?;
        Ok(())
    }

    /// Set the owner index mapping for a (owner, token) pair
    ///
    /// Maps owner address + token to the account that holds the balance
    pub fn set_owner_index(
        &self,
        owner: &Address,
        token: &Address,
        account_id: &AccountId,
    ) -> Result<(), StorageError> {
        let key = owner_index_key(owner, token);
        self.inner().write(ACCOUNTS_TABLE, &key, account_id)
    }

    /// Delete the owner index mapping for a (owner, token) pair
    pub fn delete_owner_index(&self, owner: &Address, token: &Address) -> Result<(), StorageError> {
        let key = owner_index_key(owner, token);
        self.inner().delete(ACCOUNTS_TABLE, &key)?;
        Ok(())
    }

    /// Set the intent hash index mapping
    ///
    /// Maps intent_hash to (account_id, order_id) for routing public intent
    /// events
    pub fn set_intent_index(
        &self,
        intent_hash: &B256,
        account_id: &AccountId,
        order_id: &OrderId,
    ) -> Result<(), StorageError> {
        let key = intent_hash_key(intent_hash);
        self.inner().write(ACCOUNTS_TABLE, &key, &(*account_id, *order_id))
    }

    /// Delete the intent hash index mapping
    pub fn delete_intent_index(&self, intent_hash: &B256) -> Result<(), StorageError> {
        let key = intent_hash_key(intent_hash);
        self.inner().delete(ACCOUNTS_TABLE, &key)?;
        Ok(())
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    use alloy_primitives::{Address, B256};
    use types_account::{
        Account,
        balance::mocks::mock_balance,
        mocks::mock_keychain,
        order::mocks::{mock_order, mock_order_with_pair},
        pair::Pair,
    };
    use types_core::AccountId;

    use crate::{ACCOUNTS_TABLE, test_helpers::mock_db};

    /// Create a mock account
    fn mock_account() -> Account {
        let id = AccountId::new_v4();
        let keychain = mock_keychain();
        Account::new_empty_account(id, keychain)
    }

    /// Tests creating a new account and retrieving it
    #[test]
    fn test_new_account() {
        let db = mock_db();
        db.create_table(ACCOUNTS_TABLE).unwrap();

        // Create the account
        let account = mock_account();
        let tx = db.new_write_tx().unwrap();
        tx.new_account(&account).unwrap();
        tx.commit().unwrap();

        // Read the account header
        let tx = db.new_read_tx().unwrap();
        let header = tx.get_account_header(&account.id).unwrap();
        assert!(header.is_some());
        let header = header.unwrap().deserialize().unwrap();
        assert_eq!(header.id, account.id);
        assert_eq!(header.keychain, account.keychain);
    }

    /// Tests adding an order and retrieving it
    #[test]
    fn test_add_and_get_order() {
        let db = mock_db();
        db.create_table(ACCOUNTS_TABLE).unwrap();

        // Create account and add order
        let account = mock_account();
        let order = mock_order();

        let tx = db.new_write_tx().unwrap();
        tx.new_account(&account).unwrap();
        tx.add_order(&account.id, &order).unwrap();
        tx.commit().unwrap();

        // Retrieve order by ID
        let tx = db.new_read_tx().unwrap();
        let retrieved = tx.get_order(&order.id).unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap().deserialize().unwrap();
        assert_eq!(retrieved.id, order.id);
    }

    /// Tests the order -> account mapping
    #[test]
    fn test_get_account_id_for_order() {
        let db = mock_db();
        db.create_table(ACCOUNTS_TABLE).unwrap();

        let account1 = mock_account();
        let account2 = mock_account();
        let order1 = mock_order();
        let order2 = mock_order();
        let order3 = mock_order();

        // Create accounts and add orders
        let tx = db.new_write_tx().unwrap();
        tx.new_account(&account1).unwrap();
        tx.new_account(&account2).unwrap();
        tx.add_order(&account1.id, &order1).unwrap();
        tx.add_order(&account1.id, &order2).unwrap();
        tx.add_order(&account2.id, &order3).unwrap();
        tx.commit().unwrap();

        // Check order -> account mappings
        let tx = db.new_read_tx().unwrap();
        assert_eq!(tx.get_account_id_for_order(&order1.id).unwrap(), Some(account1.id));
        assert_eq!(tx.get_account_id_for_order(&order2.id).unwrap(), Some(account1.id));
        assert_eq!(tx.get_account_id_for_order(&order3.id).unwrap(), Some(account2.id));
    }

    /// Tests updating a balance
    #[test]
    fn test_update_balance() {
        let db = mock_db();
        db.create_table(ACCOUNTS_TABLE).unwrap();

        let account = mock_account();
        let balance = mock_balance();
        let mint = balance.mint();
        let location = balance.location;

        // Create account and add balance
        let tx = db.new_write_tx().unwrap();
        tx.new_account(&account).unwrap();
        tx.update_balance(&account.id, &balance).unwrap();
        tx.commit().unwrap();

        // Retrieve balance
        let tx = db.new_read_tx().unwrap();
        let retrieved = tx.get_balance(&account.id, &mint, location).unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap().deserialize().unwrap();
        assert_eq!(retrieved.mint(), mint);
    }

    /// Tests removing an order
    #[test]
    fn test_remove_order() {
        let db = mock_db();
        db.create_table(ACCOUNTS_TABLE).unwrap();

        let account = mock_account();
        let order = mock_order();

        // Create account and add order
        let tx = db.new_write_tx().unwrap();
        tx.new_account(&account).unwrap();
        tx.add_order(&account.id, &order).unwrap();
        tx.commit().unwrap();

        // Verify order exists
        let tx = db.new_read_tx().unwrap();
        assert!(tx.get_order(&order.id).unwrap().is_some());
        assert!(tx.get_account_id_for_order(&order.id).unwrap().is_some());
        drop(tx);

        // Remove order
        let tx = db.new_write_tx().unwrap();
        tx.remove_order(&account.id, &order.id).unwrap();
        tx.commit().unwrap();

        // Verify order is gone
        let tx = db.new_read_tx().unwrap();
        assert!(tx.get_order(&order.id).unwrap().is_none());
        assert!(tx.get_account_id_for_order(&order.id).unwrap().is_none());
    }

    /// Tests full account reconstruction
    #[test]
    fn test_get_account_reconstruction() {
        let db = mock_db();
        db.create_table(ACCOUNTS_TABLE).unwrap();

        let account = mock_account();
        let order1 = mock_order();
        let order2 = mock_order();
        let balance1 = mock_balance();
        let mint1 = balance1.mint();

        // Create account with orders and balances
        let tx = db.new_write_tx().unwrap();
        tx.new_account(&account).unwrap();
        tx.add_order(&account.id, &order1).unwrap();
        tx.add_order(&account.id, &order2).unwrap();
        tx.update_balance(&account.id, &balance1).unwrap();
        tx.commit().unwrap();

        // Reconstruct full account
        let tx = db.new_read_tx().unwrap();
        let account = tx.get_account(&account.id).unwrap();
        assert!(account.is_some());
        let account = account.unwrap();

        // Verify header
        assert_eq!(account.id, account.id);
        assert_eq!(account.keychain, account.keychain);

        // Verify orders
        assert_eq!(account.orders.len(), 2);
        assert!(account.orders.contains_key(&order1.id));
        assert!(account.orders.contains_key(&order2.id));

        // Verify balances
        assert_eq!(account.balances.len(), 1);
        assert!(account.balances.contains_key(&mint1));
    }

    /// Tests getting orders with a specific input token
    #[test]
    fn test_get_orders_with_input_token() {
        let db = mock_db();
        db.create_table(ACCOUNTS_TABLE).unwrap();

        // Create account
        let account = mock_account();
        let tx = db.new_write_tx().unwrap();
        tx.new_account(&account).unwrap();

        // Create orders with different input tokens
        let mint1 = Address::from([1u8; 20]);
        let mint2 = Address::from([2u8; 20]);
        let mint3 = Address::from([3u8; 20]);

        let pair1 = Pair::new(mint1, mint2);
        let pair2 = Pair::new(mint1, mint3); // Same input token as pair1
        let pair3 = Pair::new(mint2, mint1); // Different input token

        let order1 = mock_order_with_pair(pair1);
        let order2 = mock_order_with_pair(pair2);
        let order3 = mock_order_with_pair(pair3);

        // Add all orders to the account
        tx.add_order(&account.id, &order1).unwrap();
        tx.add_order(&account.id, &order2).unwrap();
        tx.add_order(&account.id, &order3).unwrap();
        tx.commit().unwrap();

        // Test: Get orders with mint1 as input token
        let tx = db.new_read_tx().unwrap();
        let orders_with_mint1 = tx.get_orders_with_input_token(&account.id, &mint1).unwrap();
        assert_eq!(orders_with_mint1.len(), 2);
        assert!(orders_with_mint1.contains(&order1.id));
        assert!(orders_with_mint1.contains(&order2.id));
        assert!(!orders_with_mint1.contains(&order3.id));

        // Test: Get orders with mint2 as input token
        let orders_with_mint2 = tx.get_orders_with_input_token(&account.id, &mint2).unwrap();
        assert_eq!(orders_with_mint2.len(), 1);
        assert_eq!(orders_with_mint2[0], order3.id);

        // Test: Get orders with a mint that has no orders
        let mint4 = Address::from([4u8; 20]);
        let orders_with_mint4 = tx.get_orders_with_input_token(&account.id, &mint4).unwrap();
        assert!(orders_with_mint4.is_empty());
    }

    /// Tests getting all accounts
    #[test]
    fn test_get_all_accounts() {
        let db = mock_db();
        db.create_table(ACCOUNTS_TABLE).unwrap();

        // Create multiple accounts with different data
        let account1 = mock_account();
        let account2 = mock_account();
        let account3 = mock_account();

        let order1 = mock_order();
        let order2 = mock_order();
        let balance1 = mock_balance();
        let mint1 = balance1.mint();

        // Create accounts with various combinations of orders and balances
        let tx = db.new_write_tx().unwrap();
        tx.new_account(&account1).unwrap();
        tx.add_order(&account1.id, &order1).unwrap();
        tx.update_balance(&account1.id, &balance1).unwrap();

        tx.new_account(&account2).unwrap();
        tx.add_order(&account2.id, &order2).unwrap();

        tx.new_account(&account3).unwrap();
        tx.commit().unwrap();

        // Get all accounts
        let tx = db.new_read_tx().unwrap();
        let all_accounts = tx.get_all_accounts().unwrap();

        // Verify we got all 3 accounts
        assert_eq!(all_accounts.len(), 3);

        // Verify account1 has order and balance
        let acc1 = all_accounts.iter().find(|a| a.id == account1.id).unwrap();
        assert_eq!(acc1.orders.len(), 1);
        assert!(acc1.orders.contains_key(&order1.id));
        assert_eq!(acc1.balances.len(), 1);
        assert!(acc1.balances.contains_key(&mint1));

        // Verify account2 has order but no balance
        let acc2 = all_accounts.iter().find(|a| a.id == account2.id).unwrap();
        assert_eq!(acc2.orders.len(), 1);
        assert!(acc2.orders.contains_key(&order2.id));
        assert_eq!(acc2.balances.len(), 0);

        // Verify account3 has no orders or balances
        let acc3 = all_accounts.iter().find(|a| a.id == account3.id).unwrap();
        assert_eq!(acc3.orders.len(), 0);
        assert_eq!(acc3.balances.len(), 0);
    }

    // --- Owner Index Tests ---

    /// Tests setting and getting owner index
    #[test]
    fn test_owner_index_set_get() {
        let db = mock_db();
        db.create_table(ACCOUNTS_TABLE).unwrap();

        let account = mock_account();
        let owner = Address::from([0xAA; 20]);
        let token = Address::from([0xBB; 20]);

        // Set owner index
        let tx = db.new_write_tx().unwrap();
        tx.new_account(&account).unwrap();
        tx.set_owner_index(&owner, &token, &account.id).unwrap();
        tx.commit().unwrap();

        // Get owner index
        let tx = db.new_read_tx().unwrap();
        let result = tx.get_account_for_owner(&owner, &token).unwrap();
        assert_eq!(result, Some(account.id));
    }

    /// Tests deleting owner index
    #[test]
    fn test_owner_index_delete() {
        let db = mock_db();
        db.create_table(ACCOUNTS_TABLE).unwrap();

        let account = mock_account();
        let owner = Address::from([0xAA; 20]);
        let token = Address::from([0xBB; 20]);

        // Set and verify
        let tx = db.new_write_tx().unwrap();
        tx.new_account(&account).unwrap();
        tx.set_owner_index(&owner, &token, &account.id).unwrap();
        tx.commit().unwrap();

        let tx = db.new_read_tx().unwrap();
        assert!(tx.get_account_for_owner(&owner, &token).unwrap().is_some());
        drop(tx);

        // Delete and verify
        let tx = db.new_write_tx().unwrap();
        tx.delete_owner_index(&owner, &token).unwrap();
        tx.commit().unwrap();

        let tx = db.new_read_tx().unwrap();
        assert!(tx.get_account_for_owner(&owner, &token).unwrap().is_none());
    }

    /// Tests getting all owner index entries
    #[test]
    fn test_owner_index_get_all() {
        let db = mock_db();
        db.create_table(ACCOUNTS_TABLE).unwrap();

        let account1 = mock_account();
        let account2 = mock_account();
        let owner1 = Address::from([0xAA; 20]);
        let owner2 = Address::from([0xBB; 20]);
        let token1 = Address::from([0x11; 20]);
        let token2 = Address::from([0x22; 20]);

        // Set multiple owner indices
        let tx = db.new_write_tx().unwrap();
        tx.new_account(&account1).unwrap();
        tx.new_account(&account2).unwrap();
        tx.set_owner_index(&owner1, &token1, &account1.id).unwrap();
        tx.set_owner_index(&owner1, &token2, &account1.id).unwrap();
        tx.set_owner_index(&owner2, &token1, &account2.id).unwrap();
        tx.commit().unwrap();

        // Get all entries
        let tx = db.new_read_tx().unwrap();
        let entries = tx.get_all_owner_index_entries().unwrap();
        assert_eq!(entries.len(), 3);

        // Verify entries contain expected mappings
        assert!(entries.contains(&(owner1, token1, account1.id)));
        assert!(entries.contains(&(owner1, token2, account1.id)));
        assert!(entries.contains(&(owner2, token1, account2.id)));
    }

    // --- Intent Hash Index Tests ---

    /// Tests setting and getting intent hash index
    #[test]
    fn test_intent_index_set_get() {
        let db = mock_db();
        db.create_table(ACCOUNTS_TABLE).unwrap();

        let account = mock_account();
        let order = mock_order();
        let intent_hash = B256::repeat_byte(0xCC);

        // Set intent index
        let tx = db.new_write_tx().unwrap();
        tx.new_account(&account).unwrap();
        tx.add_order(&account.id, &order).unwrap();
        tx.set_intent_index(&intent_hash, &account.id, &order.id).unwrap();
        tx.commit().unwrap();

        // Get intent index
        let tx = db.new_read_tx().unwrap();
        let result = tx.get_order_for_intent_hash(&intent_hash).unwrap();
        assert_eq!(result, Some((account.id, order.id)));
    }

    /// Tests deleting intent hash index
    #[test]
    fn test_intent_index_delete() {
        let db = mock_db();
        db.create_table(ACCOUNTS_TABLE).unwrap();

        let account = mock_account();
        let order = mock_order();
        let intent_hash = B256::repeat_byte(0xCC);

        // Set and verify
        let tx = db.new_write_tx().unwrap();
        tx.new_account(&account).unwrap();
        tx.add_order(&account.id, &order).unwrap();
        tx.set_intent_index(&intent_hash, &account.id, &order.id).unwrap();
        tx.commit().unwrap();

        let tx = db.new_read_tx().unwrap();
        assert!(tx.get_order_for_intent_hash(&intent_hash).unwrap().is_some());
        drop(tx);

        // Delete and verify
        let tx = db.new_write_tx().unwrap();
        tx.delete_intent_index(&intent_hash).unwrap();
        tx.commit().unwrap();

        let tx = db.new_read_tx().unwrap();
        assert!(tx.get_order_for_intent_hash(&intent_hash).unwrap().is_none());
    }
}
