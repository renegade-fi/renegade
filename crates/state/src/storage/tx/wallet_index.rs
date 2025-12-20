//! Helpers for accessing wallet index information in the database

use circuit_types::wallet::Nullifier;
use common::types::wallet::{OrderIdentifier, Wallet, WalletAuthenticationPath, WalletIdentifier};
use libmdbx::{RW, TransactionKind};
use util::res_some;

use crate::{
    NULLIFIER_TO_WALLET_TABLE, ORDER_TO_WALLET_TABLE, WALLETS_TABLE, storage::error::StorageError,
};

use super::StateTxn;

/// The error message emitted when a wallet is not found
const ERR_WALLET_NOT_FOUND: &str = "Wallet not found";

/// Get the key for a nullifier to wallet mapping
fn nullifier_to_wallet_key(nullifier: &Nullifier) -> String {
    format!("nullifier-{nullifier}")
}

/// Get the key for a wallet id to nullifier mapping
fn wallet_id_to_nullifiers_key(wallet_id: &WalletIdentifier) -> String {
    format!("wallet-id-nullifier-{wallet_id}")
}

// -----------
// | Getters |
// -----------

impl<T: TransactionKind> StateTxn<'_, T> {
    /// Get the wallet associated with the given ID
    pub fn get_wallet(&self, wallet_id: &WalletIdentifier) -> Result<Option<Wallet>, StorageError> {
        self.inner().read(WALLETS_TABLE, wallet_id)
    }

    /// Get the wallet ID managing a given order
    pub fn get_wallet_id_for_order(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<Option<WalletIdentifier>, StorageError> {
        self.inner().read(ORDER_TO_WALLET_TABLE, order_id)
    }

    /// Get the wallet for a given order
    pub fn get_wallet_for_order(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<Option<Wallet>, StorageError> {
        let wallet_id = res_some!(self.get_wallet_id_for_order(order_id)?);
        self.get_wallet(&wallet_id)
    }

    /// Get the wallet associated with a given nullifier
    pub fn get_wallet_for_nullifier(
        &self,
        nullifier: &Nullifier,
    ) -> Result<Option<WalletIdentifier>, StorageError> {
        let key = nullifier_to_wallet_key(nullifier);
        self.inner().read(NULLIFIER_TO_WALLET_TABLE, &key)
    }

    /// Get the nullifier for a wallet
    pub fn get_nullifier_for_wallet(
        &self,
        wallet_id: &WalletIdentifier,
    ) -> Result<Option<Nullifier>, StorageError> {
        let key = wallet_id_to_nullifiers_key(wallet_id);
        self.inner().read(NULLIFIER_TO_WALLET_TABLE, &key)
    }

    /// Get all the wallets in the database
    pub fn get_all_wallets(&self) -> Result<Vec<Wallet>, StorageError> {
        // Create a cursor and take only the values
        let wallet_cursor =
            self.inner().cursor::<WalletIdentifier, Wallet>(WALLETS_TABLE)?.into_iter();
        let wallets = wallet_cursor.values().collect::<Result<Vec<_>, _>>()?;

        Ok(wallets)
    }
}

// -----------
// | Setters |
// -----------

impl StateTxn<'_, RW> {
    /// Write a wallet to the table
    pub fn write_wallet(&self, wallet: &Wallet) -> Result<(), StorageError> {
        let nullifier = wallet.get_wallet_nullifier();
        self.update_wallet_nullifier_mapping(wallet.wallet_id, nullifier)?;
        self.inner().write(WALLETS_TABLE, &wallet.wallet_id, wallet)
    }

    /// Add a Merkle proof to the wallet
    pub fn add_wallet_merkle_proof(
        &self,
        wallet_id: &WalletIdentifier,
        proof: WalletAuthenticationPath,
    ) -> Result<(), StorageError> {
        let mut wallet = self
            .get_wallet(wallet_id)?
            .ok_or(StorageError::NotFound(ERR_WALLET_NOT_FOUND.to_string()))?;
        wallet.merkle_proof = Some(proof);

        self.write_wallet(&wallet)
    }

    /// Update the mapping from order to wallet for each of the given orders
    pub fn index_orders(
        &self,
        wallet_id: &WalletIdentifier,
        orders: &[OrderIdentifier],
    ) -> Result<(), StorageError> {
        for order in orders.iter() {
            self.inner().write(ORDER_TO_WALLET_TABLE, order, wallet_id)?;
        }

        Ok(())
    }

    /// Update the wallet ID <-> nullifier mapping
    fn update_wallet_nullifier_mapping(
        &self,
        wallet_id: WalletIdentifier,
        nullifier: Nullifier,
    ) -> Result<(), StorageError> {
        let old_nullifier = self.get_nullifier_for_wallet(&wallet_id)?;
        // Delete the old nullifier -> wallet mapping
        if let Some(nullifier) = old_nullifier {
            let nullifier_key = nullifier_to_wallet_key(&nullifier);
            self.inner().delete(NULLIFIER_TO_WALLET_TABLE, &nullifier_key)?;
        }

        // Update the nullifier -> wallet mapping and the wallet -> nullifier mapping
        let nullifier_key = nullifier_to_wallet_key(&nullifier);
        let wallet_id_key = wallet_id_to_nullifiers_key(&wallet_id);
        self.inner().write(NULLIFIER_TO_WALLET_TABLE, &nullifier_key, &wallet_id)?;
        self.inner().write(NULLIFIER_TO_WALLET_TABLE, &wallet_id_key, &nullifier)
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    use common::types::{
        wallet::{OrderIdentifier, WalletIdentifier},
        wallet_mocks::{mock_empty_wallet, mock_merkle_path},
    };
    use itertools::Itertools;

    use crate::{
        NULLIFIER_TO_WALLET_TABLE, ORDER_TO_WALLET_TABLE, WALLETS_TABLE, test_helpers::mock_db,
    };

    /// Tests adding a wallet then retrieving it
    #[test]
    fn test_add_wallet() {
        let db = mock_db();
        db.create_table(WALLETS_TABLE).unwrap();

        // Write the wallet
        let wallet = mock_empty_wallet();
        let tx = db.new_write_tx().unwrap();
        tx.write_wallet(&wallet).unwrap();
        tx.commit().unwrap();

        // Read the wallet
        let tx = db.new_read_tx().unwrap();
        let wallet_res = tx.get_wallet(&wallet.wallet_id).unwrap();
        assert_eq!(wallet_res, Some(wallet));
    }

    /// Tests adding a Merkle proof to a wallet
    #[test]
    fn test_add_merkle_proof() {
        let db = mock_db();
        db.create_table(WALLETS_TABLE).unwrap();

        // Write the wallet
        let wallet = mock_empty_wallet();
        let tx = db.new_write_tx().unwrap();
        tx.write_wallet(&wallet).unwrap();
        tx.commit().unwrap();

        // Add a Merkle proof
        let proof = mock_merkle_path();
        let tx = db.new_write_tx().unwrap();
        tx.add_wallet_merkle_proof(&wallet.wallet_id, proof.clone()).unwrap();
        tx.commit().unwrap();

        // Read the wallet
        let tx = db.new_read_tx().unwrap();
        let wallet_res = tx.get_wallet(&wallet.wallet_id).unwrap();
        assert_eq!(wallet_res.unwrap().merkle_proof, Some(proof));
    }

    /// Tests creating multiple wallets and retrieving them all
    #[test]
    fn test_get_all_wallets() {
        let db = mock_db();
        db.create_table(WALLETS_TABLE).unwrap();

        const N: usize = 10;
        let mut wallets = (0..N).map(|_| mock_empty_wallet()).collect_vec();
        let tx = db.new_write_tx().unwrap();
        for wallet in wallets.iter() {
            tx.write_wallet(wallet).unwrap();
        }
        tx.commit().unwrap();

        // Read the wallets
        let tx = db.new_read_tx().unwrap();
        let mut wallets_res = tx.get_all_wallets().unwrap();

        // Sort for comparison
        wallets_res.sort_by_key(|wallet| wallet.wallet_id);
        wallets.sort_by_key(|wallet| wallet.wallet_id);
        assert_eq!(wallets_res, wallets);
    }

    /// Tests adding a wallet for an order then retrieving it
    #[test]
    fn test_get_wallet_id_for_order() {
        let db = mock_db();
        db.create_table(ORDER_TO_WALLET_TABLE).unwrap();

        // Write the mapping
        let order_id1 = OrderIdentifier::new_v4();
        let order_id2 = OrderIdentifier::new_v4();
        let order_id3 = OrderIdentifier::new_v4();
        let wallet_id1 = WalletIdentifier::new_v4();
        let wallet_id2 = WalletIdentifier::new_v4();

        let tx = db.new_write_tx().unwrap();
        tx.index_orders(&wallet_id1, &[order_id1, order_id2]).unwrap();
        tx.index_orders(&wallet_id2, &[order_id3]).unwrap();
        tx.commit().unwrap();

        // Check all order mappings
        let tx = db.new_read_tx().unwrap();
        let wallet_res1 = tx.get_wallet_id_for_order(&order_id1).unwrap();
        assert_eq!(wallet_res1, Some(wallet_id1));
        let wallet_res2 = tx.get_wallet_id_for_order(&order_id2).unwrap();
        assert_eq!(wallet_res2, Some(wallet_id1));
        let wallet_res3 = tx.get_wallet_id_for_order(&order_id3).unwrap();
        assert_eq!(wallet_res3, Some(wallet_id2));
    }

    /// Tests the nullifier <-> wallet ID mappings
    #[test]
    fn test_nullifier_wallet_mapping() {
        let db = mock_db();
        db.create_table(WALLETS_TABLE).unwrap();
        db.create_table(NULLIFIER_TO_WALLET_TABLE).unwrap();

        // Create and write a wallet
        let mut wallet = mock_empty_wallet();
        let initial_nullifier = wallet.get_wallet_nullifier();

        let tx = db.new_write_tx().unwrap();
        tx.write_wallet(&wallet).unwrap();
        tx.commit().unwrap();

        // Test initial mapping
        let tx = db.new_read_tx().unwrap();
        let wallet_id = tx.get_wallet_for_nullifier(&initial_nullifier).unwrap();
        assert_eq!(wallet_id, Some(wallet.wallet_id));

        let nullifier = tx.get_nullifier_for_wallet(&wallet.wallet_id).unwrap();
        assert_eq!(nullifier, Some(initial_nullifier));

        // Update wallet with a new nullifier
        wallet.reblind_wallet();
        let new_nullifier = wallet.get_wallet_nullifier();

        let tx = db.new_write_tx().unwrap();
        tx.write_wallet(&wallet).unwrap();
        tx.commit().unwrap();

        // Test updated mapping
        let tx = db.new_read_tx().unwrap();
        let wallet_id = tx.get_wallet_for_nullifier(&new_nullifier).unwrap();
        assert_eq!(wallet_id, Some(wallet.wallet_id));

        let nullifier = tx.get_nullifier_for_wallet(&wallet.wallet_id).unwrap();
        assert_eq!(nullifier, Some(new_nullifier));

        // Ensure old nullifier mapping is removed
        let wallet_id = tx.get_wallet_for_nullifier(&initial_nullifier).unwrap();
        assert_eq!(wallet_id, None);
    }
}
