//! Helpers for accessing Merkle authentication paths (proofs) in the database
#![allow(missing_docs)]

use alloy_primitives::Address;
use darkpool_types::rkyv_remotes::AddressDef;
use libmdbx::{RW, TransactionKind};
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};
use types_account::{MerkleAuthenticationPath, account::OrderId};
use types_core::AccountId;

use crate::{
    MERKLE_PROOFS_TABLE,
    storage::{ArchivedValue, error::StorageError},
};

use super::StateTxn;

/// Type alias for an archived Merkle authentication path value
pub type MerkleProofValue<'a> = ArchivedValue<'a, MerkleAuthenticationPath>;

/// The type of Merkle proof being stored
#[derive(
    Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Archive, RkyvDeserialize, RkyvSerialize,
)]
#[rkyv(derive(Debug))]
pub enum MerkleProofType {
    /// A proof for an intent commitment
    Intent {
        /// The order ID for the intent
        order_id: OrderId,
    },
    /// A proof for a balance commitment
    Balance {
        /// The account ID
        account_id: AccountId,
        /// The mint address
        #[rkyv(with = AddressDef)]
        mint: Address,
    },
}

// -----------
// | Helpers |
// -----------

/// Create a key for a Merkle proof based on its type
fn proof_key(proof_type: &MerkleProofType) -> String {
    match proof_type {
        MerkleProofType::Intent { order_id } => format!("intent:{order_id}"),
        MerkleProofType::Balance { account_id, mint } => {
            format!("balance:{account_id}:{mint:?}")
        },
    }
}

// -----------
// | Getters |
// -----------

impl<T: TransactionKind> StateTxn<'_, T> {
    /// Get the Merkle authentication path for a given proof type
    pub fn get_merkle_proof(
        &self,
        proof_type: &MerkleProofType,
    ) -> Result<Option<MerkleProofValue<'_>>, StorageError> {
        let key = proof_key(proof_type);
        self.inner().read(MERKLE_PROOFS_TABLE, &key)
    }
}

// -----------
// | Setters |
// -----------

impl StateTxn<'_, RW> {
    /// Store a Merkle authentication path for a given proof type
    pub fn set_merkle_proof(
        &self,
        proof_type: &MerkleProofType,
        proof: &MerkleAuthenticationPath,
    ) -> Result<(), StorageError> {
        let key = proof_key(proof_type);
        self.inner().write(MERKLE_PROOFS_TABLE, &key, proof)
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    use alloy_primitives::Address;
    use types_account::{account::OrderId, mocks::mock_merkle_path};
    use types_core::AccountId;

    use crate::{
        MERKLE_PROOFS_TABLE, storage::tx::merkle_proofs::MerkleProofType, test_helpers::mock_db,
    };

    /// Tests storing and retrieving a Merkle proof for an intent
    #[test]
    fn test_intent_merkle_proof() {
        let db = mock_db();
        db.create_table(MERKLE_PROOFS_TABLE).unwrap();

        let intent_id = OrderId::new_v4();
        let proof = mock_merkle_path();
        let proof_type = MerkleProofType::Intent { order_id: intent_id };

        // Write the proof
        let tx = db.new_write_tx().unwrap();
        tx.set_merkle_proof(&proof_type, &proof).unwrap();
        tx.commit().unwrap();

        // Read the proof
        let tx = db.new_read_tx().unwrap();
        let stored_proof = tx.get_merkle_proof(&proof_type).unwrap();
        assert!(stored_proof.is_some());
        let retrieved = stored_proof.unwrap().deserialize().unwrap();
        assert_eq!(retrieved, proof);
    }

    /// Tests storing and retrieving a Merkle proof for a balance
    #[test]
    fn test_balance_merkle_proof() {
        let db = mock_db();
        db.create_table(MERKLE_PROOFS_TABLE).unwrap();

        let account_id = AccountId::new_v4();
        let mint = Address::ZERO; // Use a simple address for testing
        let proof = mock_merkle_path();
        let proof_type = MerkleProofType::Balance { account_id, mint };

        // Write the proof
        let tx = db.new_write_tx().unwrap();
        tx.set_merkle_proof(&proof_type, &proof).unwrap();
        tx.commit().unwrap();

        // Read the proof
        let tx = db.new_read_tx().unwrap();
        let stored_proof = tx.get_merkle_proof(&proof_type).unwrap();
        assert!(stored_proof.is_some());
        let retrieved = stored_proof.unwrap().deserialize().unwrap();
        assert_eq!(retrieved, proof);
    }

    /// Tests that intent and balance proofs are stored separately
    #[test]
    fn test_separate_intent_and_balance_proofs() {
        let db = mock_db();
        db.create_table(MERKLE_PROOFS_TABLE).unwrap();

        let intent_id = OrderId::new_v4();
        let account_id = AccountId::new_v4();
        let mint = Address::ZERO;
        let intent_proof = mock_merkle_path();
        let balance_proof = mock_merkle_path();

        let intent_proof_type = MerkleProofType::Intent { order_id: intent_id };
        let balance_proof_type = MerkleProofType::Balance { account_id, mint };

        // Write both proofs
        let tx = db.new_write_tx().unwrap();
        tx.set_merkle_proof(&intent_proof_type, &intent_proof).unwrap();
        tx.set_merkle_proof(&balance_proof_type, &balance_proof).unwrap();
        tx.commit().unwrap();

        // Verify they are stored separately
        let tx = db.new_read_tx().unwrap();
        let stored_intent_proof = tx.get_merkle_proof(&intent_proof_type).unwrap();
        let stored_balance_proof = tx.get_merkle_proof(&balance_proof_type).unwrap();
        assert!(stored_intent_proof.is_some());
        assert!(stored_balance_proof.is_some());
        assert_eq!(stored_intent_proof.unwrap().deserialize().unwrap(), intent_proof);
        assert_eq!(stored_balance_proof.unwrap().deserialize().unwrap(), balance_proof);

        // Verify they don't interfere with each other
        let wrong_intent_type = MerkleProofType::Intent { order_id: account_id };
        let wrong_balance_type = MerkleProofType::Balance { account_id: intent_id, mint };
        assert!(tx.get_merkle_proof(&wrong_intent_type).unwrap().is_none());
        assert!(tx.get_merkle_proof(&wrong_balance_type).unwrap().is_none());
    }
}
