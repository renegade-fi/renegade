//! Transaction helpers for storing and retrieving proofs

use common::types::{
    proof_bundles::{
        OrderValidityProofBundle, OrderValidityWitnessBundle, ValidWalletUpdateBundle,
    },
    wallet::OrderIdentifier,
};
use libmdbx::{RO, RW};

use crate::{PROOFS_TABLE, storage::error::StorageError};

use super::StateTxn;

// -----------
// | Helpers |
// -----------

/// Build the key for an orders validity proof bundle
#[inline]
fn validity_proof_bundle_key(order_id: &OrderIdentifier) -> String {
    format!("validity-proof-bundle:{order_id}")
}

/// Build the key for an orders validity proof witness
#[inline]
fn validity_proof_witness_key(order_id: &OrderIdentifier) -> String {
    format!("validity-proof-witness:{order_id}")
}

/// Build the key for an orders cancellation proof
#[inline]
fn cancellation_proof_key(order_id: &OrderIdentifier) -> String {
    format!("cancellation-proof:{order_id}")
}

// -----------
// | Getters |
// -----------

impl StateTxn<'_, RO> {
    // --- Interface --- //

    /// Get the validity proof bundle for an order
    pub fn get_validity_proof_bundle(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<Option<OrderValidityProofBundle>, StorageError> {
        let key = validity_proof_bundle_key(order_id);
        self.inner().read(PROOFS_TABLE, &key)
    }

    /// Get the validity proof witness for an order
    pub fn get_validity_proof_witness(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<Option<OrderValidityWitnessBundle>, StorageError> {
        let key = validity_proof_witness_key(order_id);
        self.inner().read(PROOFS_TABLE, &key)
    }

    /// Get the cancellation proof for an order
    pub fn get_cancellation_proof(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<Option<ValidWalletUpdateBundle>, StorageError> {
        let key = cancellation_proof_key(order_id);
        self.inner().read(PROOFS_TABLE, &key)
    }
}

// -----------
// | Setters |
// -----------

impl StateTxn<'_, RW> {
    /// Write a validity proof bundle for an order
    pub fn write_validity_proof_bundle(
        &self,
        order_id: &OrderIdentifier,
        proof: &OrderValidityProofBundle,
    ) -> Result<(), StorageError> {
        let key = validity_proof_bundle_key(order_id);
        self.inner().write(PROOFS_TABLE, &key, proof)
    }

    /// Write a validity proof witness for an order
    pub fn write_validity_proof_witness(
        &self,
        order_id: &OrderIdentifier,
        witness: &OrderValidityWitnessBundle,
    ) -> Result<(), StorageError> {
        let key = validity_proof_witness_key(order_id);
        self.inner().write(PROOFS_TABLE, &key, witness)
    }

    /// Write a cancellation proof for an order
    pub fn write_cancellation_proof(
        &self,
        order_id: &OrderIdentifier,
        proof: &ValidWalletUpdateBundle,
    ) -> Result<(), StorageError> {
        let key = cancellation_proof_key(order_id);
        self.inner().write(PROOFS_TABLE, &key, proof)
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use common::types::proof_bundles::mocks::{
        dummy_valid_wallet_update_bundle, dummy_validity_proof_bundle,
        dummy_validity_witness_bundle,
    };

    use crate::test_helpers::mock_db;

    use super::*;

    /// Tests writing a validity proof bundle for an order
    #[test]
    fn test_write_validity_proof_bundle() {
        let db = mock_db();
        db.create_table(PROOFS_TABLE).unwrap();

        // Read the bundle when none exists
        let order_id = OrderIdentifier::new_v4();
        let tx = db.new_read_tx().unwrap();
        let stored_proof = tx.get_validity_proof_bundle(&order_id).unwrap();
        assert!(stored_proof.is_none());
        tx.commit().unwrap();

        // Write the validity proof bundle
        let proof = dummy_validity_proof_bundle();
        let tx = db.new_write_tx().unwrap();
        tx.write_validity_proof_bundle(&order_id, &proof).unwrap();
        tx.commit().unwrap();

        // Read the validity proof bundle
        let tx = db.new_read_tx().unwrap();
        let stored_proof = tx.get_validity_proof_bundle(&order_id).unwrap();
        assert!(stored_proof.is_some());
        tx.commit().unwrap();
    }

    /// Tests writing a validity proof witness for an order
    #[test]
    fn test_write_validity_proof_witness() {
        let db = mock_db();
        db.create_table(PROOFS_TABLE).unwrap();

        // Read the witness when none exists
        let order_id = OrderIdentifier::new_v4();
        let tx = db.new_read_tx().unwrap();
        let stored_witness = tx.get_validity_proof_witness(&order_id).unwrap();
        assert!(stored_witness.is_none());
        tx.commit().unwrap();

        // Write the validity proof witness
        let witness = dummy_validity_witness_bundle();
        let tx = db.new_write_tx().unwrap();
        tx.write_validity_proof_witness(&order_id, &witness).unwrap();
        tx.commit().unwrap();

        // Read the validity proof witness
        let tx = db.new_read_tx().unwrap();
        let stored_witness = tx.get_validity_proof_witness(&order_id).unwrap();
        assert!(stored_witness.is_some());
        tx.commit().unwrap();
    }

    /// Tests writing a cancellation proof for an order
    #[test]
    fn test_write_cancellation_proof() {
        let db = mock_db();
        db.create_table(PROOFS_TABLE).unwrap();

        // Read the proof when none exists
        let order_id = OrderIdentifier::new_v4();
        let tx = db.new_read_tx().unwrap();
        let stored_proof = tx.get_cancellation_proof(&order_id).unwrap();
        assert!(stored_proof.is_none());
        tx.commit().unwrap();

        // Write the cancellation proof
        let proof = Arc::new(dummy_valid_wallet_update_bundle());
        let tx = db.new_write_tx().unwrap();
        tx.write_cancellation_proof(&order_id, &proof).unwrap();
        tx.commit().unwrap();

        // Read the cancellation proof
        let tx = db.new_read_tx().unwrap();
        let stored_proof = tx.get_cancellation_proof(&order_id).unwrap();
        assert!(stored_proof.is_some());
        tx.commit().unwrap();
    }
}
