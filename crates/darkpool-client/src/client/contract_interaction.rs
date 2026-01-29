//! Defines `DarkpoolClient` helpers that allow for interacting with the
//! darkpool contract

use alloy::consensus::constants::SELECTOR_LEN;
use alloy::rpc::types::TransactionReceipt;
use alloy_primitives::{Address, Selector};
use circuit_types::Nullifier;
use circuit_types::{elgamal::EncryptionKey, fixed_point::FixedPoint, merkle::MerkleRoot};
use constants::Scalar;
use crypto::fields::{scalar_to_u256, u256_to_scalar};
use renegade_solidity_abi::v2::IDarkpoolV2::{
    self, DepositAuth, DepositProofBundle, ObligationBundle, SettlementBundle,
};
use tracing::{info, instrument};
use types_proofs::{ValidBalanceCreateBundle, ValidDepositBundle};
use util::telemetry::helpers::backfill_trace_field;

use crate::errors::DarkpoolClientError;

use super::DarkpoolClient;

/// The set of known selectors for the Solidity darkpool
/// TODO: Add known selectors
const KNOWN_SELECTORS: [[u8; SELECTOR_LEN]; 0] = [];

impl DarkpoolClient {
    // -----------
    // | GETTERS |
    // -----------

    /// Get the current Merkle root in the contract
    #[instrument(skip_all, err)]
    pub async fn get_merkle_root(&self) -> Result<Scalar, DarkpoolClientError> {
        let depth = self.merkle_depth();
        self.darkpool
            .getMerkleRoot(depth)
            .call()
            .await
            .map_err(DarkpoolClientError::contract_interaction)
            .map(u256_to_scalar)
    }

    /// Get the default protocol fee
    #[instrument(skip_all, err)]
    pub async fn get_default_protocol_fee(&self) -> Result<FixedPoint, DarkpoolClientError> {
        self.darkpool
            .getDefaultProtocolFee()
            .call()
            .await
            .map_err(DarkpoolClientError::contract_interaction)
            .map(|r| r.into())
    }

    /// Get the base fee charged by the contract
    #[instrument(skip_all, err, fields(in_token = %in_token, out_token = %out_token))]
    pub async fn get_protocol_fee(
        &self,
        in_token: Address,
        out_token: Address,
    ) -> Result<FixedPoint, DarkpoolClientError> {
        self.darkpool
            .getProtocolFee(in_token, out_token)
            .call()
            .await
            .map_err(DarkpoolClientError::contract_interaction)
            .map(|r| r.into())
    }

    /// Get the protocol pubkey
    #[instrument(skip_all, err)]
    pub async fn get_protocol_pubkey(&self) -> Result<EncryptionKey, DarkpoolClientError> {
        let pubkey = self
            .darkpool()
            .getProtocolFeeKey()
            .call()
            .await
            .map_err(DarkpoolClientError::contract_interaction)?;

        let x = u256_to_scalar(pubkey.point.x);
        let y = u256_to_scalar(pubkey.point.y);
        Ok(EncryptionKey { x, y })
    }

    /// Get the protocol fee address
    #[instrument(skip_all, err)]
    pub async fn get_protocol_fee_addr(&self) -> Result<Address, DarkpoolClientError> {
        self.darkpool
            .getProtocolFeeRecipient()
            .call()
            .await
            .map_err(DarkpoolClientError::contract_interaction)
    }

    /// Check whether a given root is in the contract's history
    #[instrument(skip_all, err, fields(root = %root))]
    pub async fn check_merkle_root(&self, root: MerkleRoot) -> Result<bool, DarkpoolClientError> {
        let root_u256 = scalar_to_u256(&root);
        self.darkpool()
            .rootInHistory(root_u256)
            .call()
            .await
            .map_err(DarkpoolClientError::contract_interaction)
    }

    /// Check whether a given nullifier is used
    #[instrument(skip_all, err, fields(nullifier = %nullifier))]
    pub async fn is_nullifier_spent(
        &self,
        nullifier: Nullifier,
    ) -> Result<bool, DarkpoolClientError> {
        let nullifier_u256 = scalar_to_u256(&nullifier);
        self.darkpool()
            .nullifierSpent(nullifier_u256)
            .call()
            .await
            .map_err(DarkpoolClientError::contract_interaction)
    }

    /// Whether a given selector is known to the darkpool implementation
    ///
    /// This method is used in share recovery to decide whether a top level
    /// trace calls the darkpool directly. If not, the relayer should trace the
    /// transaction's calls and parse shares from darkpool subcalls.
    pub fn is_known_selector(selector: Selector) -> bool {
        KNOWN_SELECTORS.contains(&selector.0)
    }

    // -----------
    // | SETTERS |
    // -----------

    /// Create a new balance in the darkpool contract
    ///
    /// Awaits until the transaction is confirmed on-chain
    #[instrument(skip_all, err, fields(
        tx_hash,
        recovery_id = %proof_bundle.statement.recovery_id
    ))]
    pub async fn create_balance(
        &self,
        auth: DepositAuth,
        proof_bundle: ValidBalanceCreateBundle,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        let bundle = proof_bundle.into_inner();
        let contract_statement: IDarkpoolV2::ValidBalanceCreateStatement = bundle.statement.into();
        let proof = bundle.proof.into();

        let calldata_bundle = IDarkpoolV2::NewBalanceDepositProofBundle {
            merkleDepth: self.merkle_depth(),
            statement: contract_statement,
            proof,
        };
        let tx = self.darkpool().depositNewBalance(auth, calldata_bundle);
        let receipt = self.send_tx(tx).await?;

        let tx_hash = format!("{:#x}", receipt.transaction_hash);
        backfill_trace_field("tx_hash", &tx_hash);
        info!("`create_balance` tx hash: {tx_hash}");

        Ok(receipt)
    }

    /// Deposit funds into an existing balance in the darkpool contract
    ///
    /// Awaits until the transaction is confirmed on-chain
    #[instrument(skip_all, err, fields(
        tx_hash,
        recovery_id = %proof_bundle.statement.recovery_id
    ))]
    pub async fn deposit(
        &self,
        auth: DepositAuth,
        proof_bundle: ValidDepositBundle,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        let bundle = proof_bundle.into_inner();
        let contract_statement: IDarkpoolV2::ValidDepositStatement = bundle.statement.into();
        let proof = bundle.proof.into();

        let calldata_bundle = DepositProofBundle {
            merkleDepth: self.merkle_depth(),
            statement: contract_statement,
            proof,
        };
        let tx = self.darkpool().deposit(auth, calldata_bundle);
        let receipt = self.send_tx(tx).await?;

        let tx_hash = format!("{:#x}", receipt.transaction_hash);
        backfill_trace_field("tx_hash", &tx_hash);
        info!("`deposit` tx hash: {tx_hash}");

        Ok(receipt)
    }

    /// Settle a match
    pub async fn settle_match(
        &self,
        obligation_bundle: ObligationBundle,
        settlement_bundle0: SettlementBundle,
        settlement_bundle1: SettlementBundle,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        let tx =
            self.darkpool().settleMatch(obligation_bundle, settlement_bundle0, settlement_bundle1);
        let receipt = self.send_tx(tx).await?;

        let tx_hash = format!("{:#x}", receipt.transaction_hash);
        backfill_trace_field("tx_hash", &tx_hash);
        info!("`settle_match` tx hash: {tx_hash}");

        Ok(receipt)
    }

    // -----------
    // | Testing |
    // -----------

    /// Clear the Merkle tree for testing
    #[cfg(feature = "integration")]
    pub async fn clear_merkle_tree(&self) -> Result<TransactionReceipt, DarkpoolClientError> {
        unimplemented!("clear_merkle_tree not yet implemented for Solidity darkpool")
    }
}
