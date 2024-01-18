//! Defines `ArbitrumClient` helpers that allow for interacting with the
//! darkpool contract

use circuit_types::{merkle::MerkleRoot, wallet::Nullifier};
use common::types::proof_bundles::{
    GenericMatchSettleBundle, GenericValidWalletCreateBundle, GenericValidWalletUpdateBundle,
    MatchBundle, OrderValidityProofBundle, SizedValidWalletCreateBundle,
    SizedValidWalletUpdateBundle,
};
use constants::Scalar;
use contracts_common::types::MatchPayload;
use renegade_crypto::fields::{scalar_to_u256, u256_to_scalar};
use tracing::log::info;

use crate::{
    conversion::{
        build_match_linking_proofs, build_match_proofs, to_contract_proof,
        to_contract_valid_commitments_statement, to_contract_valid_match_settle_statement,
        to_contract_valid_reblind_statement, to_contract_valid_wallet_create_statement,
        to_contract_valid_wallet_update_statement,
    },
    errors::ArbitrumClientError,
    helpers::{send_tx, serialize_calldata},
};

use super::ArbitrumClient;

impl ArbitrumClient {
    // -----------
    // | GETTERS |
    // -----------

    /// Get the current Merkle root in the contract
    pub async fn get_merkle_root(&self) -> Result<Scalar, ArbitrumClientError> {
        self.darkpool_contract
            .get_root()
            .call()
            .await
            .map_err(|e| ArbitrumClientError::ContractInteraction(e.to_string()))
            .map(|r| u256_to_scalar(&r))
    }

    /// Check whether the given Merkle root is a valid historical root
    pub async fn check_merkle_root_valid(
        &self,
        root: MerkleRoot,
    ) -> Result<bool, ArbitrumClientError> {
        self.darkpool_contract
            .root_in_history(scalar_to_u256(&root))
            .call()
            .await
            .map_err(|e| ArbitrumClientError::ContractInteraction(e.to_string()))
    }

    /// Check whether the given nullifier is used
    pub async fn check_nullifier_used(
        &self,
        nullifier: Nullifier,
    ) -> Result<bool, ArbitrumClientError> {
        self.darkpool_contract
            .is_nullifier_spent(scalar_to_u256(&nullifier))
            .call()
            .await
            .map_err(|e| ArbitrumClientError::ContractInteraction(e.to_string()))
    }

    // -----------
    // | SETTERS |
    // -----------

    /// Call the `new_wallet` contract method with the given
    /// `VALID WALLET CREATE` statement
    ///
    /// Awaits until the transaction is confirmed on-chain
    pub async fn new_wallet(
        &self,
        valid_wallet_create: &SizedValidWalletCreateBundle,
    ) -> Result<(), ArbitrumClientError> {
        let GenericValidWalletCreateBundle { statement, proof } = valid_wallet_create;

        let contract_proof = to_contract_proof(proof)?;
        let proof_calldata = serialize_calldata(&contract_proof)?;

        let contract_statement = to_contract_valid_wallet_create_statement(statement);
        let valid_wallet_create_statement_calldata = serialize_calldata(&contract_statement)?;

        let receipt = send_tx(
            self.darkpool_contract
                .new_wallet(proof_calldata, valid_wallet_create_statement_calldata),
        )
        .await?;

        info!("`new_wallet` tx hash: {:#x}", receipt.transaction_hash);

        Ok(())
    }

    /// Call the `update_wallet` contract method with the given
    /// `VALID WALLET UPDATE` statement
    ///
    /// Awaits until the transaction is confirmed on-chain
    pub async fn update_wallet(
        &self,
        valid_wallet_update: &SizedValidWalletUpdateBundle,
        statement_signature: Vec<u8>,
    ) -> Result<(), ArbitrumClientError> {
        let GenericValidWalletUpdateBundle { statement, proof } = valid_wallet_update;

        let contract_proof = to_contract_proof(proof)?;
        let proof_calldata = serialize_calldata(&contract_proof)?;

        let contract_statement = to_contract_valid_wallet_update_statement(statement)?;
        let valid_wallet_update_statement_calldata = serialize_calldata(&contract_statement)?;

        let receipt = send_tx(self.darkpool_contract.update_wallet(
            proof_calldata,
            valid_wallet_update_statement_calldata,
            statement_signature.into(),
        ))
        .await?;

        info!("`update_wallet` tx hash: {:#x}", receipt.transaction_hash);

        Ok(())
    }

    /// Call the `process_match_settle` contract method with the given
    /// match payloads and `VALID MATCH SETTLE` statement
    ///
    /// Awaits until the transaction is confirmed on-chain
    pub async fn process_match_settle(
        &self,
        party0_validity_proofs: &OrderValidityProofBundle,
        party1_validity_proofs: &OrderValidityProofBundle,
        match_bundle: &MatchBundle,
    ) -> Result<(), ArbitrumClientError> {
        // Destructure proof bundles

        let GenericMatchSettleBundle {
            statement: valid_match_settle_statement,
            proof: valid_match_settle_proof,
        } = match_bundle.copy_match_proof();

        let party_0_valid_commitments_statement = party0_validity_proofs.commitment_proof.statement;

        let party_0_valid_reblind_statement =
            party0_validity_proofs.reblind_proof.statement.clone();

        let party_1_valid_commitments_statement = party1_validity_proofs.commitment_proof.statement;

        let party_1_valid_reblind_statement =
            party1_validity_proofs.reblind_proof.statement.clone();

        let party_0_match_payload = MatchPayload {
            valid_commitments_statement: to_contract_valid_commitments_statement(
                party_0_valid_commitments_statement,
            ),
            valid_reblind_statement: to_contract_valid_reblind_statement(
                &party_0_valid_reblind_statement,
            ),
        };

        let party_1_match_payload = MatchPayload {
            valid_commitments_statement: to_contract_valid_commitments_statement(
                party_1_valid_commitments_statement,
            ),
            valid_reblind_statement: to_contract_valid_reblind_statement(
                &party_1_valid_reblind_statement,
            ),
        };

        let match_proofs = build_match_proofs(
            party0_validity_proofs,
            party1_validity_proofs,
            &valid_match_settle_proof,
        )
        .map_err(ArbitrumClientError::Conversion)?;

        let match_link_proofs = build_match_linking_proofs(
            party0_validity_proofs,
            party1_validity_proofs,
            match_bundle,
        )
        .map_err(ArbitrumClientError::Conversion)?;

        // Serialize calldata

        let party_0_match_payload_calldata = serialize_calldata(&party_0_match_payload)?;
        let party_1_match_payload_calldata = serialize_calldata(&party_1_match_payload)?;

        let contract_valid_match_settle_statement =
            to_contract_valid_match_settle_statement(&valid_match_settle_statement);
        let valid_match_settle_statement_calldata =
            serialize_calldata(&contract_valid_match_settle_statement)?;

        let match_proofs_calldata = serialize_calldata(&match_proofs)?;
        let match_link_proofs_calldata = serialize_calldata(&match_link_proofs)?;

        // Call `process_match_settle` on darkpool contract

        let receipt = send_tx(self.darkpool_contract.process_match_settle(
            party_0_match_payload_calldata,
            party_1_match_payload_calldata,
            valid_match_settle_statement_calldata,
            match_proofs_calldata,
            match_link_proofs_calldata,
        ))
        .await?;

        info!("`process_match_settle` tx hash: {:#x}", receipt.transaction_hash);

        Ok(())
    }
}
