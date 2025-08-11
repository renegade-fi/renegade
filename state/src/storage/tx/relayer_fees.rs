//! Storage helpers for relayer fees

use circuit_types::fixed_point::FixedPoint;
use libmdbx::{RW, TransactionKind};

use crate::{RELAYER_FEES_TABLE, storage::error::StorageError};

use super::StateTxn;

/// Construct a key for a wallet's relayer fee
fn relayer_fee_key(ticker: &str) -> String {
    format!("relayer-fee-{}", ticker.to_lowercase())
}

// -----------
// | Getters |
// -----------

impl<T: TransactionKind> StateTxn<'_, T> {
    /// Get the relayer fee for a ticker
    ///
    /// Defaults to the default relayer fee if no fee is set
    pub fn get_relayer_fee(&self, ticker: &str) -> Result<FixedPoint, StorageError> {
        let key = relayer_fee_key(ticker);
        let maybe_fee = self.inner().read(RELAYER_FEES_TABLE, &key)?;
        let fee = match maybe_fee {
            Some(fee) => fee,
            None => self.get_default_relayer_fee()?,
        };

        Ok(fee)
    }
}

// -----------
// | Setters |
// -----------

impl StateTxn<'_, RW> {
    /// Set the relayer fee for a ticker
    pub fn set_asset_relayer_fee(&self, ticker: &str, fee: FixedPoint) -> Result<(), StorageError> {
        let key = relayer_fee_key(ticker);
        self.inner().write(RELAYER_FEES_TABLE, &key, &fee)
    }
}

#[cfg(test)]
mod tests {
    use circuit_types::fixed_point::FixedPoint;

    use crate::test_helpers::mock_db;

    /// Tests the case in which a fee is not set for a wallet
    #[test]
    fn test_no_fee_set() {
        let default_fee = FixedPoint::from_f64_round_down(0.0002);
        let ticker = "USDC";

        let db = mock_db();
        let tx = db.new_write_tx().unwrap();

        tx.set_default_relayer_fee(&default_fee).unwrap();
        let fee = tx.get_relayer_fee(ticker).unwrap();
        assert_eq!(fee, default_fee);
    }

    /// Tests the case in which a fee is set for a wallet
    #[test]
    fn test_fee_set() {
        let ticker = "USDC";
        let fee = FixedPoint::from_f64_round_down(0.0001);

        let db = mock_db();
        let tx = db.new_write_tx().unwrap();
        tx.set_asset_relayer_fee(ticker, fee).unwrap();
        let found_fee = tx.get_relayer_fee(ticker).unwrap();
        assert_eq!(found_fee, fee);
    }
}
