//! Transaction helpers for storing and retrieving proofs and witnesses

use libmdbx::{RW, TransactionKind};
use types_proofs::{
    ALL_VALIDITY_PROOF_KEYS, ALL_VALIDITY_WITNESS_KEYS, OUTPUT_BALANCE_VALIDITY_PROOF_KEYS,
    StoredValidityProof, StoredValidityWitness, ValidityProofBundle, ValidityProofLocator,
};

use crate::{
    PROOFS_TABLE,
    storage::{error::StorageError, traits::RkyvWith, traits::Value},
};

use super::StateTxn;

// -----------
// | Helpers |
// -----------

/// Build a storage key for a validity proof or witness
fn storage_key(type_key: &str, locator: &ValidityProofLocator) -> String {
    locator.storage_key(type_key)
}

// -----------
// | Getters |
// -----------

impl<T: TransactionKind> StateTxn<'_, T> {
    /// Read a validity proof bundle from state
    pub fn get_validity_proof<P>(
        &self,
        locator: &ValidityProofLocator,
    ) -> Result<Option<P>, StorageError>
    where
        P: StoredValidityProof,
        RkyvWith<P, P::RkyvRemote>: Value,
    {
        let key = storage_key(P::PROOF_TYPE_KEY, locator);
        let wrapped = self.inner().read::<_, RkyvWith<P, P::RkyvRemote>>(PROOFS_TABLE, &key)?;
        match wrapped {
            Some(archived) => Ok(Some(archived.deserialize_with()?)),
            None => Ok(None),
        }
    }

    /// Read a validity witness from state
    pub fn get_validity_witness<W>(
        &self,
        locator: &ValidityProofLocator,
    ) -> Result<Option<W>, StorageError>
    where
        W: StoredValidityWitness,
        RkyvWith<W, W::RkyvRemote>: Value,
    {
        let key = storage_key(W::WITNESS_TYPE_KEY, locator);
        let wrapped = self.inner().read::<_, RkyvWith<W, W::RkyvRemote>>(PROOFS_TABLE, &key)?;
        match wrapped {
            Some(archived) => Ok(Some(archived.deserialize_with()?)),
            None => Ok(None),
        }
    }

    /// Check whether any output balance validity proof exists for a locator
    pub fn has_output_balance_validity_proof(
        &self,
        locator: &ValidityProofLocator,
    ) -> Result<bool, StorageError> {
        for key_prefix in OUTPUT_BALANCE_VALIDITY_PROOF_KEYS {
            let key = storage_key(key_prefix, locator);
            if self.inner().read_bytes(PROOFS_TABLE, &key)?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

// -----------
// | Setters |
// -----------

impl StateTxn<'_, RW> {
    /// Write a validity proof bundle to state
    pub fn write_validity_proof<P>(
        &self,
        locator: &ValidityProofLocator,
        bundle: &P,
    ) -> Result<(), StorageError>
    where
        P: StoredValidityProof,
        RkyvWith<P, P::RkyvRemote>: Value,
    {
        let key = storage_key(P::PROOF_TYPE_KEY, locator);
        let wrapped = RkyvWith::<P, P::RkyvRemote>::cast(bundle);
        self.inner().write(PROOFS_TABLE, &key, wrapped)
    }

    /// Write a validity witness to state
    pub fn write_validity_witness<W>(
        &self,
        locator: &ValidityProofLocator,
        witness: &W,
    ) -> Result<(), StorageError>
    where
        W: StoredValidityWitness,
        RkyvWith<W, W::RkyvRemote>: Value,
    {
        let key = storage_key(W::WITNESS_TYPE_KEY, locator);
        let wrapped = RkyvWith::<W, W::RkyvRemote>::cast(witness);
        self.inner().write(PROOFS_TABLE, &key, wrapped)
    }

    /// Write a concrete validity proof bundle (proof + witness) to state.
    ///
    /// Writes the proof and witness to separate keys within the same
    /// transaction so that clients can deserialize each independently.
    pub fn write_validity_proof_bundle(
        &self,
        locator: &ValidityProofLocator,
        bundle: &ValidityProofBundle,
    ) -> Result<(), StorageError> {
        match bundle {
            ValidityProofBundle::IntentOnlyFirstFill { bundle, witness } => {
                self.write_validity_proof(locator, bundle)?;
                self.write_validity_witness(locator, witness)
            },
            ValidityProofBundle::IntentOnly { bundle, witness } => {
                self.write_validity_proof(locator, bundle)?;
                self.write_validity_witness(locator, witness)
            },
            ValidityProofBundle::IntentAndBalanceFirstFill { bundle, witness } => {
                self.write_validity_proof(locator, bundle)?;
                self.write_validity_witness(locator, witness)
            },
            ValidityProofBundle::IntentAndBalance { bundle, witness } => {
                self.write_validity_proof(locator, bundle)?;
                self.write_validity_witness(locator, witness)
            },
            ValidityProofBundle::NewOutputBalance { bundle, witness } => {
                self.write_validity_proof(locator, bundle)?;
                self.write_validity_witness(locator, witness)
            },
            ValidityProofBundle::OutputBalance { bundle, witness } => {
                self.write_validity_proof(locator, bundle)?;
                self.write_validity_witness(locator, witness)
            },
        }
    }

    /// Delete a specific validity proof type for an order
    pub fn delete_validity_proof<P: StoredValidityProof>(
        &self,
        locator: &ValidityProofLocator,
    ) -> Result<(), StorageError> {
        let key = storage_key(P::PROOF_TYPE_KEY, locator);
        self.inner().delete(PROOFS_TABLE, &key)?;
        Ok(())
    }

    /// Delete all validity proofs and witnesses for a locator
    pub fn delete_all_validity_proofs(
        &self,
        locator: &ValidityProofLocator,
    ) -> Result<(), StorageError> {
        for prefix in ALL_VALIDITY_PROOF_KEYS {
            let key = storage_key(prefix, locator);
            self.inner().delete(PROOFS_TABLE, &key)?;
        }
        for prefix in ALL_VALIDITY_WITNESS_KEYS {
            let key = storage_key(prefix, locator);
            self.inner().delete(PROOFS_TABLE, &key)?;
        }
        Ok(())
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    use alloy_primitives::Address;
    use types_account::account::OrderId;
    use types_core::AccountId;
    use types_proofs::{
        IntentOnlyValidityBundle, ValidityProofLocator, mocks::mock_intent_only_validity_bundle,
    };

    use crate::{PROOFS_TABLE, test_helpers::mock_db};

    /// Tests writing and retrieving a validity proof bundle
    #[test]
    fn test_write_and_get_validity_proof() {
        let db = mock_db();
        db.create_table(PROOFS_TABLE).unwrap();

        let locator = ValidityProofLocator::Intent { order_id: OrderId::new_v4() };
        let bundle = mock_intent_only_validity_bundle();

        let tx = db.new_write_tx().unwrap();
        tx.write_validity_proof::<IntentOnlyValidityBundle>(&locator, &bundle).unwrap();
        tx.commit().unwrap();

        let tx = db.new_read_tx().unwrap();
        let retrieved = tx.get_validity_proof::<IntentOnlyValidityBundle>(&locator).unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.statement.owner, bundle.statement.owner);
        assert_eq!(retrieved.statement.recovery_id, bundle.statement.recovery_id);
    }

    /// Tests that a missing proof returns None
    #[test]
    fn test_get_validity_proof_missing() {
        let db = mock_db();
        db.create_table(PROOFS_TABLE).unwrap();

        let locator = ValidityProofLocator::Intent { order_id: OrderId::new_v4() };
        let tx = db.new_read_tx().unwrap();
        let retrieved = tx.get_validity_proof::<IntentOnlyValidityBundle>(&locator).unwrap();
        assert!(retrieved.is_none());
    }

    /// Tests deleting a specific validity proof type
    #[test]
    fn test_delete_validity_proof() {
        let db = mock_db();
        db.create_table(PROOFS_TABLE).unwrap();

        let locator = ValidityProofLocator::Intent { order_id: OrderId::new_v4() };
        let bundle = mock_intent_only_validity_bundle();

        let tx = db.new_write_tx().unwrap();
        tx.write_validity_proof::<IntentOnlyValidityBundle>(&locator, &bundle).unwrap();
        tx.commit().unwrap();

        let tx = db.new_read_tx().unwrap();
        assert!(tx.get_validity_proof::<IntentOnlyValidityBundle>(&locator).unwrap().is_some());
        drop(tx);

        let tx = db.new_write_tx().unwrap();
        tx.delete_validity_proof::<IntentOnlyValidityBundle>(&locator).unwrap();
        tx.commit().unwrap();

        let tx = db.new_read_tx().unwrap();
        assert!(tx.get_validity_proof::<IntentOnlyValidityBundle>(&locator).unwrap().is_none());
    }

    /// Tests deleting all proofs for a locator
    #[test]
    fn test_delete_all_validity_proofs() {
        let db = mock_db();
        db.create_table(PROOFS_TABLE).unwrap();

        let locator = ValidityProofLocator::Intent { order_id: OrderId::new_v4() };
        let bundle = mock_intent_only_validity_bundle();

        let tx = db.new_write_tx().unwrap();
        tx.write_validity_proof::<IntentOnlyValidityBundle>(&locator, &bundle).unwrap();
        tx.commit().unwrap();

        let tx = db.new_write_tx().unwrap();
        tx.delete_all_validity_proofs(&locator).unwrap();
        tx.commit().unwrap();

        let tx = db.new_read_tx().unwrap();
        assert!(tx.get_validity_proof::<IntentOnlyValidityBundle>(&locator).unwrap().is_none());
    }

    /// Tests writing and retrieving with a balance locator key shape
    #[test]
    fn test_balance_locator_key_shape() {
        let db = mock_db();
        db.create_table(PROOFS_TABLE).unwrap();

        let locator =
            ValidityProofLocator::Balance { account_id: AccountId::new_v4(), mint: Address::ZERO };
        let bundle = mock_intent_only_validity_bundle();

        let tx = db.new_write_tx().unwrap();
        tx.write_validity_proof::<IntentOnlyValidityBundle>(&locator, &bundle).unwrap();
        tx.commit().unwrap();

        let tx = db.new_read_tx().unwrap();
        let retrieved = tx.get_validity_proof::<IntentOnlyValidityBundle>(&locator).unwrap();
        assert!(retrieved.is_some());
    }
}
