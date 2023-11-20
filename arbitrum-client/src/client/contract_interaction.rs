//! Defines `ArbitrumClient` helpers that allow for interacting with the
//! darkpool contract

use circuit_types::{merkle::MerkleRoot, wallet::Nullifier, PlonkProof};
use constants::Scalar;

use crate::{
    errors::ArbitrumClientError,
    helpers::{deserialize_calldata, serialize_calldata},
    serde_def_types::SerdeScalarField,
    types::{
        MatchPayload, Proof, ValidMatchSettleStatement, ValidWalletCreateStatement,
        ValidWalletUpdateStatement,
    },
};

use super::ArbitrumClient;

// TODO: Replace `renegade_contracts_common::types::*` with relayer statement
// types once they're adapted to Plonk

impl ArbitrumClient {
    // -----------
    // | GETTERS |
    // -----------

    /// Get the current Merkle root in the contract
    pub async fn get_merkle_root(&self) -> Result<Scalar, ArbitrumClientError> {
        let merkle_root_bytes = self
            .darkpool_contract
            .get_root()
            .call()
            .await
            .map_err(|e| ArbitrumClientError::ContractInteraction(e.to_string()))?;

        let merkle_root = deserialize_calldata::<SerdeScalarField>(&merkle_root_bytes)?.0;

        Ok(Scalar::new(merkle_root))
    }

    /// Check whether the given Merkle root is a valid historical root
    pub async fn check_merkle_root_valid(
        &self,
        root: MerkleRoot,
    ) -> Result<bool, ArbitrumClientError> {
        let root_calldata = serialize_calldata(&SerdeScalarField(root.inner()))?;

        self.darkpool_contract
            .root_in_history(root_calldata)
            .call()
            .await
            .map_err(|e| ArbitrumClientError::ContractInteraction(e.to_string()))
    }

    /// Check whether the given nullifier is used
    pub async fn check_nullifier_used(
        &self,
        nullifier: Nullifier,
    ) -> Result<bool, ArbitrumClientError> {
        let nullifier_calldata = serialize_calldata(&SerdeScalarField(nullifier.inner()))?;

        self.darkpool_contract
            .is_nullifier_spent(nullifier_calldata)
            .call()
            .await
            .map_err(|e| ArbitrumClientError::ContractInteraction(e.to_string()))
    }

    // TODO: Implement analogue of `get_public_blinder_tx`

    // -----------
    // | SETTERS |
    // -----------

    /// Call the `new_wallet` contract method with the given
    /// `VALID WALLET CREATE` statement
    ///
    /// Awaits until the transaction is confirmed on-chain
    pub async fn new_wallet(
        &self,
        wallet_blinder_share: Scalar,
        valid_wallet_create_statement: ValidWalletCreateStatement,
        proof: PlonkProof,
    ) -> Result<(), ArbitrumClientError> {
        let wallet_blinder_share_calldata =
            serialize_calldata(&SerdeScalarField(wallet_blinder_share.inner()))?;
        let contract_proof: Proof = proof.try_into()?;
        let proof_calldata = serialize_calldata(&contract_proof)?;
        let valid_wallet_create_statement_calldata =
            serialize_calldata(&valid_wallet_create_statement)?;

        self.darkpool_contract
            .new_wallet(
                wallet_blinder_share_calldata,
                proof_calldata,
                valid_wallet_create_statement_calldata,
            )
            .send()
            .await
            .map_err(|e| ArbitrumClientError::ContractInteraction(e.to_string()))?
            .await
            .map_err(|e| ArbitrumClientError::ContractInteraction(e.to_string()))
            .map(|_| ())
    }

    /// Call the `update_wallet` contract method with the given
    /// `VALID WALLET UPDATE` statement
    ///
    /// Awaits until the transaction is confirmed on-chain
    pub async fn update_wallet(
        &self,
        wallet_blinder_share: Scalar,
        valid_wallet_update_statement: ValidWalletUpdateStatement,
        statement_signature: Vec<u8>,
        proof: PlonkProof,
    ) -> Result<(), ArbitrumClientError> {
        let wallet_blinder_share_calldata =
            serialize_calldata(&SerdeScalarField(wallet_blinder_share.inner()))?;
        let contract_proof: Proof = proof.try_into()?;
        let proof_calldata = serialize_calldata(&contract_proof)?;
        let valid_wallet_update_statement_calldata =
            serialize_calldata(&valid_wallet_update_statement)?;

        self.darkpool_contract
            .update_wallet(
                wallet_blinder_share_calldata,
                proof_calldata,
                valid_wallet_update_statement_calldata,
                statement_signature.into(),
            )
            .send()
            .await
            .map_err(|e| ArbitrumClientError::ContractInteraction(e.to_string()))?
            .await
            .map_err(|e| ArbitrumClientError::ContractInteraction(e.to_string()))
            .map(|_| ())
    }

    /// Call the `process_match_settle` contract method with the given
    /// match payloads and `VALID MATCH SETTLE` statement
    ///
    /// Awaits until the transaction is confirmed on-chain
    #[allow(clippy::too_many_arguments)]
    pub async fn process_match_settle(
        &self,
        party_0_match_payload: MatchPayload,
        party_0_valid_commitments_proof: PlonkProof,
        party_0_valid_reblind_proof: PlonkProof,
        party_1_match_payload: MatchPayload,
        party_1_valid_commitments_proof: PlonkProof,
        party_1_valid_reblind_proof: PlonkProof,
        valid_match_settle_statement: ValidMatchSettleStatement,
        valid_match_settle_proof: PlonkProof,
    ) -> Result<(), ArbitrumClientError> {
        let party_0_match_payload_calldata = serialize_calldata(&party_0_match_payload)?;

        let party_0_valid_commitments_proof: Proof = party_0_valid_commitments_proof.try_into()?;
        let party_0_valid_commitments_proof_calldata =
            serialize_calldata(&party_0_valid_commitments_proof)?;

        let party_0_valid_reblind_proof: Proof = party_0_valid_reblind_proof.try_into()?;
        let party_0_valid_reblind_proof_calldata =
            serialize_calldata(&party_0_valid_reblind_proof)?;

        let party_1_match_payload_calldata = serialize_calldata(&party_1_match_payload)?;

        let party_1_valid_commitments_proof: Proof = party_1_valid_commitments_proof.try_into()?;
        let party_1_valid_commitments_proof_calldata =
            serialize_calldata(&party_1_valid_commitments_proof)?;

        let party_1_valid_reblind_proof: Proof = party_1_valid_reblind_proof.try_into()?;
        let party_1_valid_reblind_proof_calldata =
            serialize_calldata(&party_1_valid_reblind_proof)?;

        let valid_match_settle_statement_calldata =
            serialize_calldata(&valid_match_settle_statement)?;

        let valid_match_settle_proof: Proof = valid_match_settle_proof.try_into()?;
        let valid_match_settle_proof_calldata = serialize_calldata(&valid_match_settle_proof)?;

        self.darkpool_contract
            .process_match_settle(
                party_0_match_payload_calldata,
                party_0_valid_commitments_proof_calldata,
                party_0_valid_reblind_proof_calldata,
                party_1_match_payload_calldata,
                party_1_valid_commitments_proof_calldata,
                party_1_valid_reblind_proof_calldata,
                valid_match_settle_statement_calldata,
                valid_match_settle_proof_calldata,
            )
            .send()
            .await
            .map_err(|e| ArbitrumClientError::ContractInteraction(e.to_string()))?
            .await
            .map_err(|e| ArbitrumClientError::ContractInteraction(e.to_string()))
            .map(|_| ())
    }
}
