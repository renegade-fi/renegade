//! Storage helpers for relayer fees

use circuit_types::fixed_point::FixedPoint;
use libmdbx::{RW, TransactionKind};

use crate::storage::error::StorageError;

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
        todo!("implement per-asset fees")
    }
}

// -----------
// | Setters |
// -----------

impl StateTxn<'_, RW> {
    /// Set the relayer fee for a ticker
    pub fn set_relayer_fee(&self, ticker: &str, fee: FixedPoint) -> Result<(), StorageError> {
        todo!("implement per-asset fees");
    }
}

#[cfg(test)]
mod tests {

    /// Tests the case in which a fee is not set for a wallet
    #[test]
    fn test_no_fee_set() {
        todo!()
    }

    /// Tests the case in which a fee is set for a wallet
    #[test]
    fn test_fee_set() {
        todo!()
    }
}
