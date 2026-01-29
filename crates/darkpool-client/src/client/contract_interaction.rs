//! Defines `DarkpoolClient` helpers that allow for interacting with the
//! darkpool contract

use alloy::rpc::types::TransactionRequest;
use alloy::{primitives::Address, rpc::types::TransactionReceipt};
use circuit_types::Nullifier;
use circuit_types::{elgamal::EncryptionKey, fixed_point::FixedPoint, merkle::MerkleRoot};
use constants::Scalar;
use renegade_solidity_abi::v2::IDarkpoolV2::{DepositAuth, ObligationBundle, SettlementBundle};
use tracing::{info, instrument};
use types_proofs::{
    IntentOnlyBoundedSettlementBundle, OrderValidityProofBundle, ValidBalanceCreateBundle,
    ValidDepositBundle,
};
use util::telemetry::helpers::backfill_trace_field;

use crate::errors::DarkpoolClientError;
use crate::traits::DarkpoolImpl;

use super::DarkpoolClientInner;

impl<D: DarkpoolImpl> DarkpoolClientInner<D> {
    // -----------
    // | GETTERS |
    // -----------

    /// Get the current Merkle root in the contract
    #[instrument(skip_all, err)]
    pub async fn get_merkle_root(&self) -> Result<Scalar, DarkpoolClientError> {
        self.darkpool.get_merkle_root().await
    }

    /// Get the base fee charged by the contract
    #[instrument(skip_all, err, fields(in_token = %in_token, out_token = %out_token))]
    pub async fn get_protocol_fee(
        &self,
        in_token: Address,
        out_token: Address,
    ) -> Result<FixedPoint, DarkpoolClientError> {
        self.darkpool.get_protocol_fee(in_token, out_token).await
    }

    /// Get the default protocol fee rate
    #[instrument(skip_all, err)]
    pub async fn get_default_protocol_fee(&self) -> Result<FixedPoint, DarkpoolClientError> {
        self.darkpool.get_default_protocol_fee().await
    }

    /// Get the protocol pubkey
    #[instrument(skip_all, err)]
    pub async fn get_protocol_pubkey(&self) -> Result<EncryptionKey, DarkpoolClientError> {
        self.darkpool.get_protocol_pubkey().await
    }

    /// Check whether a given root is in the contract's history
    #[instrument(skip_all, err, fields(root = %root))]
    pub async fn check_merkle_root(&self, root: MerkleRoot) -> Result<bool, DarkpoolClientError> {
        self.darkpool.check_merkle_root(root).await
    }

    /// Check whether a given nullifier is used
    #[instrument(skip_all, err, fields(nullifier = %nullifier))]
    pub async fn is_nullifier_spent(
        &self,
        nullifier: Nullifier,
    ) -> Result<bool, DarkpoolClientError> {
        self.darkpool.is_nullifier_spent(nullifier).await
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
        let receipt = self.darkpool.create_balance(auth, proof_bundle).await?;
        let tx_hash = format!("{:#x}", receipt.transaction_hash);
        backfill_trace_field("tx_hash", &tx_hash);
        info!("`create_balance` tx hash: {}", tx_hash);

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
        let receipt = self.darkpool.deposit(auth, proof_bundle).await?;
        let tx_hash = format!("{:#x}", receipt.transaction_hash);
        backfill_trace_field("tx_hash", &tx_hash);
        info!("`deposit` tx hash: {}", tx_hash);

        Ok(receipt)
    }

    /// Settle a match
    pub async fn settle_match(
        &self,
        obligation_bundle: ObligationBundle,
        settlement_bundle0: SettlementBundle,
        settlement_bundle1: SettlementBundle,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        let receipt = self
            .darkpool
            .settle_match(obligation_bundle, settlement_bundle0, settlement_bundle1)
            .await?;

        let tx_hash = format!("{:#x}", receipt.transaction_hash);
        backfill_trace_field("tx_hash", &tx_hash);
        info!("`settle_match` tx hash: {}", tx_hash);

        Ok(receipt)
    }

    // ----------------
    // | Calldata Gen |
    // ----------------

    /// Generate calldata for a `processAtomicMatchSEttle` call
    pub fn gen_atomic_match_settle_calldata(
        &self,
        receiver_address: Option<Address>,
        internal_party_validity_proofs: &OrderValidityProofBundle,
        match_atomic_bundle: IntentOnlyBoundedSettlementBundle,
    ) -> Result<TransactionRequest, DarkpoolClientError> {
        self.darkpool.gen_atomic_match_settle_calldata(
            receiver_address,
            internal_party_validity_proofs,
            match_atomic_bundle,
        )
    }
}
