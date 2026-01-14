//! Interface methods for Merkle authentication paths (proofs)

use alloy_primitives::Address;
use tracing::instrument;
use types_account::MerkleAuthenticationPath;
use types_account::account::OrderId;
use types_core::AccountId;

use crate::{
    error::StateError, notifications::ProposalWaiter, state_transition::StateTransition,
    storage::tx::merkle_proofs::MerkleProofType,
};

use super::StateInner;

impl StateInner {
    // -----------
    // | Getters |
    // -----------

    /// Get the Merkle authentication path for an intent by its ID
    pub async fn get_intent_merkle_proof(
        &self,
        intent_id: &OrderId,
    ) -> Result<Option<MerkleAuthenticationPath>, StateError> {
        let intent_id = *intent_id;
        let proof_type = MerkleProofType::Intent { order_id: intent_id };
        self.with_read_tx(move |tx| {
            let proof_value = tx.get_merkle_proof(&proof_type)?;
            Ok(proof_value.map(|archived| archived.deserialize()).transpose()?)
        })
        .await
    }

    /// Get the Merkle authentication path for a balance by account ID and mint
    pub async fn get_balance_merkle_proof(
        &self,
        account_id: &AccountId,
        mint: &Address,
    ) -> Result<Option<MerkleAuthenticationPath>, StateError> {
        let account_id = *account_id;
        let mint = *mint;
        let proof_type = MerkleProofType::Balance { account_id, mint };
        self.with_read_tx(move |tx| {
            let proof_value = tx.get_merkle_proof(&proof_type)?;
            Ok(proof_value.map(|archived| archived.deserialize()).transpose()?)
        })
        .await
    }

    // -----------
    // | Setters |
    // -----------

    /// Set a Merkle authentication path for an intent
    #[instrument(name = "propose_add_intent_merkle_proof", skip_all, err, fields(intent_id = %intent_id))]
    pub async fn add_intent_merkle_proof(
        &self,
        intent_id: OrderId,
        proof: MerkleAuthenticationPath,
    ) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::AddMerkleProof {
            proof_type: MerkleProofType::Intent { order_id: intent_id },
            proof,
        })
        .await
    }

    /// Set a Merkle authentication path for a balance
    #[instrument(name = "propose_add_balance_merkle_proof", skip_all, err, fields(account_id = %account_id, mint = %mint))]
    pub async fn add_balance_merkle_proof(
        &self,
        account_id: AccountId,
        mint: Address,
        proof: MerkleAuthenticationPath,
    ) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::AddMerkleProof {
            proof_type: MerkleProofType::Balance { account_id, mint },
            proof,
        })
        .await
    }
}

#[cfg(test)]
mod test {
    use darkpool_types::fuzzing::random_address;
    use types_account::{account::OrderId, mocks::mock_merkle_path};
    use types_core::AccountId;

    use crate::test_helpers::mock_state;

    /// Test adding and retrieving an intent Merkle proof end-to-end
    #[tokio::test]
    async fn test_add_intent_merkle_proof() {
        let state = mock_state().await;
        let intent_id = OrderId::new_v4();
        let proof = mock_merkle_path();

        // Initially, no proof should exist
        assert!(state.get_intent_merkle_proof(&intent_id).await.unwrap().is_none());

        // Add the proof
        let waiter = state.add_intent_merkle_proof(intent_id, proof.clone()).await.unwrap();
        waiter.await.unwrap();

        // Verify the proof was stored
        let retrieved_proof = state.get_intent_merkle_proof(&intent_id).await.unwrap().unwrap();
        assert_eq!(retrieved_proof, proof);
    }

    /// Test adding and retrieving a balance Merkle proof end-to-end
    #[tokio::test]
    async fn test_add_balance_merkle_proof() {
        let state = mock_state().await;

        let account_id = AccountId::new_v4();
        let mint = random_address();
        let proof = mock_merkle_path();

        // Initially, no proof should exist
        assert!(state.get_balance_merkle_proof(&account_id, &mint).await.unwrap().is_none());

        // Add the proof
        let waiter = state.add_balance_merkle_proof(account_id, mint, proof.clone()).await.unwrap();
        waiter.await.unwrap();

        // Verify the proof was stored
        let retrieved_proof =
            state.get_balance_merkle_proof(&account_id, &mint).await.unwrap().unwrap();
        assert_eq!(retrieved_proof, proof);
    }
}
