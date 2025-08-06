//! Defines `DarkpoolClient` helpers that allow for interacting with the
//! darkpool contract

use alloy::rpc::types::TransactionRequest;
use alloy::{primitives::Address, rpc::types::TransactionReceipt};
use circuit_types::{
    elgamal::EncryptionKey, fixed_point::FixedPoint, merkle::MerkleRoot, wallet::Nullifier,
};
use common::types::proof_bundles::{
    ValidMalleableMatchSettleAtomicBundle, ValidMatchSettleAtomicBundle, ValidMatchSettleBundle,
};
use common::types::{
    proof_bundles::{
        OrderValidityProofBundle, SizedFeeRedemptionBundle, SizedOfflineFeeSettlementBundle,
        SizedRelayerFeeSettlementBundle, SizedValidWalletCreateBundle,
        SizedValidWalletUpdateBundle,
    },
    transfer_auth::TransferAuth,
};
use constants::Scalar;
use tracing::{info, instrument};
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

    /// Get the fee charged by the contract
    #[instrument(skip_all, err)]
    pub async fn get_protocol_fee(&self) -> Result<FixedPoint, DarkpoolClientError> {
        self.darkpool.get_protocol_fee().await
    }

    /// Get the external match fee override for the given mint
    #[instrument(skip_all, err, fields(mint = %mint))]
    pub async fn get_external_match_fee(
        &self,
        mint: Address,
    ) -> Result<FixedPoint, DarkpoolClientError> {
        self.darkpool.get_external_match_fee(mint).await
    }

    /// Get the public encryption key used for protocol fees
    #[instrument(skip_all, err)]
    pub async fn get_protocol_pubkey(&self) -> Result<EncryptionKey, DarkpoolClientError> {
        self.darkpool.get_protocol_pubkey().await
    }

    /// Check whether the given Merkle root is a valid historical root
    #[instrument(skip_all, err, fields(root = %root))]
    pub async fn check_merkle_root_valid(
        &self,
        root: MerkleRoot,
    ) -> Result<bool, DarkpoolClientError> {
        self.darkpool.check_merkle_root(root).await
    }

    /// Check whether the given nullifier is used
    ///
    /// Returns `true` if the nullifier is used, `false` otherwise
    #[instrument(skip_all, err, fields(nullifier = %nullifier))]
    pub async fn check_nullifier_used(
        &self,
        nullifier: Nullifier,
    ) -> Result<bool, DarkpoolClientError> {
        self.darkpool.is_nullifier_spent(nullifier).await
    }

    /// Check whether the given public blinder is used
    ///
    /// Returns `true` if the blinder is used, `false` otherwise
    #[instrument(skip_all, err, fields(blinder = %blinder))]
    pub async fn is_public_blinder_used(
        &self,
        blinder: Scalar,
    ) -> Result<bool, DarkpoolClientError> {
        self.darkpool.is_blinder_used(blinder).await
    }

    // -----------
    // | SETTERS |
    // -----------

    /// Call the `new_wallet` contract method with the given
    /// `VALID WALLET CREATE` statement
    ///
    /// Awaits until the transaction is confirmed on-chain
    #[instrument(skip_all, err, fields(
        tx_hash,
        blinder = %valid_wallet_create.statement.public_wallet_shares.blinder
    ))]
    pub async fn new_wallet(
        &self,
        valid_wallet_create: &SizedValidWalletCreateBundle,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        let receipt = self.darkpool.new_wallet(valid_wallet_create).await?;
        let tx_hash = format!("{:#x}", receipt.transaction_hash);
        backfill_trace_field("tx_hash", &tx_hash);
        info!("`new_wallet` tx hash: {}", tx_hash);

        Ok(receipt)
    }

    /// Call the `update_wallet` contract method with the given
    /// `VALID WALLET UPDATE` statement
    ///
    /// Awaits until the transaction is confirmed on-chain
    #[instrument(skip_all, err, fields(
        tx_hash,
        blinder = %valid_wallet_update.statement.new_public_shares.blinder
    ))]
    pub async fn update_wallet(
        &self,
        valid_wallet_update: &SizedValidWalletUpdateBundle,
        wallet_commitment_signature: Vec<u8>,
        transfer_auth: Option<TransferAuth>,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        let receipt = self
            .darkpool
            .update_wallet(valid_wallet_update, wallet_commitment_signature, transfer_auth)
            .await?;
        let tx_hash = format!("{:#x}", receipt.transaction_hash);

        backfill_trace_field("tx_hash", &tx_hash);
        info!("`update_wallet` tx hash: {}", tx_hash);
        Ok(receipt)
    }

    /// Call the `process_match_settle` contract method with the given
    /// match payloads and `VALID MATCH SETTLE` statement
    ///
    /// Awaits until the transaction is confirmed on-chain
    #[instrument(skip_all, err, fields(
        tx_hash,
        party0_blinder = %match_bundle.statement.party0_modified_shares.blinder,
        party1_blinder = %match_bundle.statement.party1_modified_shares.blinder
    ))]
    pub async fn process_match_settle(
        &self,
        party0_validity_proofs: &OrderValidityProofBundle,
        party1_validity_proofs: &OrderValidityProofBundle,
        match_bundle: ValidMatchSettleBundle,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        let receipt = self
            .darkpool
            .process_match_settle(party0_validity_proofs, party1_validity_proofs, match_bundle)
            .await?;
        let tx_hash = format!("{:#x}", receipt.transaction_hash);

        backfill_trace_field("tx_hash", &tx_hash);
        info!("`process_match_settle` tx hash: {}", tx_hash);
        Ok(receipt)
    }

    /// Return the tx parameters for a `process_atomic_match_settle` call
    ///
    /// We do not submit the transaction here, as atomic matches are settled by
    /// the external party
    pub fn gen_atomic_match_settle_calldata(
        &self,
        receiver_address: Option<Address>,
        internal_party_validity_proofs: &OrderValidityProofBundle,
        match_atomic_bundle: ValidMatchSettleAtomicBundle,
    ) -> Result<TransactionRequest, DarkpoolClientError> {
        self.darkpool.gen_atomic_match_settle_calldata(
            receiver_address,
            internal_party_validity_proofs,
            match_atomic_bundle,
        )
    }

    /// Generate tx parameters for a `process_malleable_atomic_match_settle`
    /// call
    pub fn gen_malleable_atomic_match_settle_calldata(
        &self,
        receiver_address: Option<Address>,
        internal_party_validity_proofs: &OrderValidityProofBundle,
        match_atomic_bundle: ValidMalleableMatchSettleAtomicBundle,
    ) -> Result<TransactionRequest, DarkpoolClientError> {
        self.darkpool.gen_malleable_atomic_match_settle_calldata(
            receiver_address,
            internal_party_validity_proofs,
            match_atomic_bundle,
        )
    }

    /// Call the `settle_online_relayer_fee` contract method with the given
    /// `VALID RELAYER FEE SETTLEMENT` statement
    ///
    /// Awaits until the transaction is confirmed on-chain
    #[instrument(skip_all, err, fields(
        tx_hash,
        sender_blinder = %valid_relayer_fee_settlement.statement.sender_updated_public_shares.blinder,
        recipient_blinder = %valid_relayer_fee_settlement.statement.recipient_updated_public_shares.blinder,
    ))]
    pub async fn settle_online_relayer_fee(
        &self,
        valid_relayer_fee_settlement: &SizedRelayerFeeSettlementBundle,
        relayer_wallet_commitment_signature: Vec<u8>,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        let receipt = self
            .darkpool
            .settle_online_relayer_fee(
                valid_relayer_fee_settlement,
                relayer_wallet_commitment_signature,
            )
            .await?;
        let tx_hash = format!("{:#x}", receipt.transaction_hash);

        backfill_trace_field("tx_hash", &tx_hash);
        info!("`settle_online_relayer_fee` tx hash: {}", tx_hash);
        Ok(receipt)
    }

    /// Call the `settle_offline_fee` contract method with the given
    /// `VALID OFFLINE FEE SETTLEMENT` statement
    ///
    /// Awaits until the transaction is confirmed on-chain
    #[instrument(skip_all, err, fields(
        tx_hash,
        blinder = %valid_offline_fee_settlement.statement.updated_wallet_public_shares.blinder
    ))]
    pub async fn settle_offline_fee(
        &self,
        valid_offline_fee_settlement: &SizedOfflineFeeSettlementBundle,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        let receipt = self.darkpool.settle_offline_fee(valid_offline_fee_settlement).await?;
        let tx_hash = format!("{:#x}", receipt.transaction_hash);
        backfill_trace_field("tx_hash", &tx_hash);
        info!("`settle_offline_fee` tx hash: {}", tx_hash);

        Ok(receipt)
    }

    /// Call the `redeem_fee` contract method with the given
    /// `VALID FEE REDEMPTION` statement
    ///
    /// Awaits until the transaction is confirmed on-chain
    #[instrument(skip_all, err, fields(
        tx_hash,
        blinder = %valid_fee_redemption.statement.new_wallet_public_shares.blinder
    ))]
    pub async fn redeem_fee(
        &self,
        valid_fee_redemption: &SizedFeeRedemptionBundle,
        recipient_wallet_commitment_signature: Vec<u8>,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        let receipt = self
            .darkpool
            .redeem_fee(valid_fee_redemption, recipient_wallet_commitment_signature)
            .await?;
        let tx_hash = format!("{:#x}", receipt.transaction_hash);

        backfill_trace_field("tx_hash", &tx_hash);
        info!("`redeem_fee` tx hash: {}", tx_hash);
        Ok(receipt)
    }
}
