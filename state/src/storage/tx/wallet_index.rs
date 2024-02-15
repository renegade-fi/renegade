//! Helpers for accessing wallet index information in the database

use common::types::wallet::{OrderIdentifier, Wallet, WalletAuthenticationPath, WalletIdentifier};
use libmdbx::{TransactionKind, RW};

use crate::{storage::error::StorageError, ORDER_TO_WALLET_TABLE, WALLETS_TABLE};

use super::StateTxn;

/// The error message emitted when a wallet is not found
const ERR_WALLET_NOT_FOUND: &str = "Wallet not found";

// -----------
// | Getters |
// -----------

impl<'db, T: TransactionKind> StateTxn<'db, T> {
    /// Get the wallet associated with the given ID
    pub fn get_wallet(&self, wallet_id: &WalletIdentifier) -> Result<Option<Wallet>, StorageError> {
        self.inner().read(WALLETS_TABLE, wallet_id)
    }

    /// Get the wallet managing a given order
    pub fn get_wallet_for_order(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<Option<WalletIdentifier>, StorageError> {
        self.inner().read(ORDER_TO_WALLET_TABLE, order_id)
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

impl<'db> StateTxn<'db, RW> {
    /// Write a wallet to the table
    pub fn write_wallet(&self, wallet: &Wallet) -> Result<(), StorageError> {
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

    use crate::{test_helpers::mock_db, ORDER_TO_WALLET_TABLE, WALLETS_TABLE};

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
    fn test_get_wallet_for_order() {
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
        let wallet_res1 = tx.get_wallet_for_order(&order_id1).unwrap();
        assert_eq!(wallet_res1, Some(wallet_id1));
        let wallet_res2 = tx.get_wallet_for_order(&order_id2).unwrap();
        assert_eq!(wallet_res2, Some(wallet_id1));
        let wallet_res3 = tx.get_wallet_for_order(&order_id3).unwrap();
        assert_eq!(wallet_res3, Some(wallet_id2));
    }
}
