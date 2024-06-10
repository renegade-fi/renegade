//! Storage helpers for relayer fees

use circuit_types::fixed_point::FixedPoint;
use common::types::wallet::WalletIdentifier;
use libmdbx::{TransactionKind, RW};

use crate::{storage::error::StorageError, RELAYER_FEES_TABLE};

use super::StateTxn;

/// Construct a key for a wallet's relayer fee
fn relayer_fee_key(wallet_id: &WalletIdentifier) -> String {
    format!("relayer-fee-{}", wallet_id)
}

// -----------
// | Getters |
// -----------

impl<'db, T: TransactionKind> StateTxn<'db, T> {
    /// Get the relayer fee for a wallet
    ///
    /// Defaults to the default relayer fee if no fee is set
    pub fn get_relayer_fee(
        &self,
        wallet_id: &WalletIdentifier,
    ) -> Result<FixedPoint, StorageError> {
        let key = relayer_fee_key(wallet_id);
        let value = match self.inner().read(RELAYER_FEES_TABLE, &key)? {
            Some(fee) => fee,
            None => self.get_relayer_take_rate()?,
        };

        Ok(value)
    }
}

// -----------
// | Setters |
// -----------

impl<'db> StateTxn<'db, RW> {
    /// Set the relayer fee for a wallet
    pub fn set_relayer_fee(
        &self,
        wallet_id: &WalletIdentifier,
        fee: FixedPoint,
    ) -> Result<(), StorageError> {
        let key = relayer_fee_key(wallet_id);
        self.inner().write(RELAYER_FEES_TABLE, &key, &fee)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use circuit_types::fixed_point::FixedPoint;
    use common::types::wallet::WalletIdentifier;

    use crate::test_helpers::mock_db;

    /// Tests the case in which a fee is not set for a wallet
    #[test]
    fn test_no_fee_set() {
        let db = mock_db();
        let wallet_id = WalletIdentifier::new_v4();

        // Setup the default fee
        let fee = FixedPoint::from_f64_round_down(0.01);
        let tx = db.new_write_tx().unwrap();
        tx.set_relayer_take_rate(&fee).unwrap();
        tx.commit().unwrap();

        // Ensure the fee is set correctly
        let tx = db.new_read_tx().unwrap();
        let found_fee = tx.get_relayer_fee(&wallet_id).unwrap();
        assert_eq!(found_fee, fee);
    }

    /// Tests the case in which a fee is set for a wallet
    #[test]
    fn test_fee_set() {
        let db = mock_db();
        let wallet_id = WalletIdentifier::new_v4();
        let fee = FixedPoint::from_f64_round_down(0.01);
        let wallet_fee = FixedPoint::from_f64_round_down(0.02);

        let tx = db.new_write_tx().unwrap();
        tx.set_relayer_take_rate(&fee).unwrap();
        tx.set_relayer_fee(&wallet_id, wallet_fee).unwrap();
        tx.commit().unwrap();

        // Ensure the fee is set correctly
        let tx = db.new_read_tx().unwrap();
        let fee = tx.get_relayer_fee(&wallet_id).unwrap();
        assert_eq!(fee, wallet_fee);
    }
}
