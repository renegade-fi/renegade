//! Defines `ArbitrumClient` helpers that allow for interacting with the
//! darkpool contract

use circuit_types::{merkle::MerkleRoot, wallet::Nullifier};
use constants::{Scalar, ScalarField, SystemProof};
use renegade_contracts_common::{
    serde_def_types::SerdeScalarField,
    types::{ValidWalletCreateStatement, ValidWalletUpdateStatement, ValidMatchSettleStatement},
};

use crate::{
    conversion::ToContractType,
    errors::ArbitrumClientError,
    helpers::{deserialize_retdata, serialize_calldata}, types::MatchPayload,
};

use super::ArbitrumClient;

// TODO: Replace `renegade_contracts_common::types::*` with relayer statement
// types once they're adapted to Plonk

impl ArbitrumClient {
    // -----------
    // | GETTERS |
    // -----------

    /// Get the current Merkle root in the contract
    pub async fn get_merkle_root(&self) -> Result<ScalarField, ArbitrumClientError> {
        let merkle_root_bytes = self
            .darkpool_contract
            .get_root()
            .call()
            .await
            .map_err(|e| ArbitrumClientError::ContractInteraction(e.to_string()))?;

        Ok(deserialize_retdata::<SerdeScalarField>(&merkle_root_bytes)?.0)
    }

    /// Check whether the given Merkle root is a valid historical root
    pub async fn check_merkle_root_valid(
        &self,
        root: MerkleRoot,
    ) -> Result<bool, ArbitrumClientError> {
        self.darkpool_contract
            .root_in_history(serialize_calldata(&SerdeScalarField(root.inner()))?)
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
            .is_nullifier_spent(serialize_calldata(&SerdeScalarField(nullifier.inner()))?)
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
        proof: SystemProof,
    ) -> Result<(), ArbitrumClientError> {
        self.darkpool_contract
            .new_wallet(
                serialize_calldata(&SerdeScalarField(wallet_blinder_share.inner()))?,
                serialize_calldata(&proof.to_contract_type()?)?,
                serialize_calldata(&valid_wallet_create_statement)?,
            )
            .send()
            .await
            .map_err(|e| ArbitrumClientError::ContractInteraction(e.to_string()))?
            .await
            .map_err(|e| ArbitrumClientError::ContractInteraction(e.to_string()))?;

        Ok(())
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
        proof: SystemProof,
    ) -> Result<(), ArbitrumClientError> {
        self.darkpool_contract
            .update_wallet(
                serialize_calldata(&SerdeScalarField(wallet_blinder_share.inner()))?,
                serialize_calldata(&proof.to_contract_type()?)?,
                serialize_calldata(&valid_wallet_update_statement)?,
                statement_signature.into(),
            )
            .send()
            .await
            .map_err(|e| ArbitrumClientError::ContractInteraction(e.to_string()))?
            .await
            .map_err(|e| ArbitrumClientError::ContractInteraction(e.to_string()))?;

        Ok(())
    }

    /// Call the `process_match_settle` contract method with the given
    /// match payloads and `VALID MATCH SETTLE` statement
    /// 
    /// Awaits until the transaction is confirmed on-chain
    #[allow(clippy::too_many_arguments)]
    pub async fn process_match_settle(
        &self,
        party_0_match_payload: MatchPayload,
        party_0_valid_commitments_proof: SystemProof,
        party_0_valid_reblind_proof: SystemProof,
        party_1_match_payload: MatchPayload,
        party_1_valid_commitments_proof: SystemProof,
        party_1_valid_reblind_proof: SystemProof,
        valid_match_settle_statement: ValidMatchSettleStatement,
        valid_match_settle_proof: SystemProof,
    ) -> Result<(), ArbitrumClientError> {
        self.darkpool_contract
            .process_match_settle(
                serialize_calldata(&party_0_match_payload.to_contract_type()?)?,
                serialize_calldata(&party_0_valid_commitments_proof.to_contract_type()?)?,
                serialize_calldata(&party_0_valid_reblind_proof.to_contract_type()?)?,
                serialize_calldata(&party_1_match_payload.to_contract_type()?)?,
                serialize_calldata(&party_1_valid_commitments_proof.to_contract_type()?)?,
                serialize_calldata(&party_1_valid_reblind_proof.to_contract_type()?)?,
                serialize_calldata(&valid_match_settle_statement)?,
                serialize_calldata(&valid_match_settle_proof.to_contract_type()?)?,
            )
            .send()
            .await
            .map_err(|e| ArbitrumClientError::ContractInteraction(e.to_string()))?
            .await
            .map_err(|e| ArbitrumClientError::ContractInteraction(e.to_string()))?;

        Ok(())
    }
}
