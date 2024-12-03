//! Defines `ArbitrumClient` helpers that allow for interacting with the
//! darkpool contract

use circuit_types::{
    elgamal::EncryptionKey, fixed_point::FixedPoint, merkle::MerkleRoot, wallet::Nullifier,
};
use common::types::{
    proof_bundles::{
        AtomicMatchSettleBundle, GenericFeeRedemptionBundle, GenericMatchSettleAtomicBundle,
        GenericMatchSettleBundle, GenericOfflineFeeSettlementBundle,
        GenericRelayerFeeSettlementBundle, GenericValidWalletCreateBundle,
        GenericValidWalletUpdateBundle, MatchBundle, OrderValidityProofBundle,
        SizedFeeRedemptionBundle, SizedOfflineFeeSettlementBundle, SizedRelayerFeeSettlementBundle,
        SizedValidWalletCreateBundle, SizedValidWalletUpdateBundle,
    },
    transfer_auth::TransferAuth,
};
use constants::Scalar;
use contracts_common::types::MatchPayload;
use ethers::{
    abi::Detokenize,
    contract::ContractCall,
    providers::Middleware,
    types::{
        transaction::eip2718::TypedTransaction, Address, BlockNumber, Bytes, TransactionReceipt,
    },
};
use renegade_crypto::fields::{scalar_to_u256, u256_to_scalar};
use tracing::{info, instrument};
use util::{err_str, telemetry::helpers::backfill_trace_field};

#[cfg(feature = "tx-metrics")]
use renegade_metrics::helpers::{decr_inflight_txs, incr_inflight_txs};

use crate::{
    conversion::{
        build_atomic_match_linking_proofs, build_atomic_match_proofs, build_match_linking_proofs,
        build_match_proofs, to_contract_proof, to_contract_transfer_aux_data,
        to_contract_valid_commitments_statement, to_contract_valid_fee_redemption_statement,
        to_contract_valid_match_settle_atomic_statement, to_contract_valid_match_settle_statement,
        to_contract_valid_offline_fee_settlement_statement, to_contract_valid_reblind_statement,
        to_contract_valid_relayer_fee_settlement_statement,
        to_contract_valid_wallet_create_statement, to_contract_valid_wallet_update_statement,
    },
    errors::ArbitrumClientError,
    helpers::serialize_calldata,
};

use super::{ArbitrumClient, MiddlewareStack};

impl ArbitrumClient {
    // -----------
    // | GETTERS |
    // -----------

    /// Get the current Merkle root in the contract
    #[instrument(skip_all, err)]
    pub async fn get_merkle_root(&self) -> Result<Scalar, ArbitrumClientError> {
        self.get_darkpool_client()
            .get_root()
            .call()
            .await
            .map_err(|e| ArbitrumClientError::ContractInteraction(e.to_string()))
            .map(|r| u256_to_scalar(&r))
    }

    /// Get the fee charged by the contract
    #[instrument(skip_all, err)]
    pub async fn get_protocol_fee(&self) -> Result<FixedPoint, ArbitrumClientError> {
        // The contract returns the repr of the fee as a u256
        self.get_darkpool_client()
            .get_fee()
            .call()
            .await
            .map_err(err_str!(ArbitrumClientError::ContractInteraction))
            .map(|r| FixedPoint::from_repr(u256_to_scalar(&r)))
    }

    /// Get the public encryption key used for protocol fees
    #[instrument(skip_all, err)]
    pub async fn get_protocol_pubkey(&self) -> Result<EncryptionKey, ArbitrumClientError> {
        let pubkey = self
            .get_darkpool_client()
            .get_pubkey()
            .call()
            .await
            .map_err(err_str!(ArbitrumClientError::ContractInteraction))?;

        Ok(EncryptionKey { x: u256_to_scalar(&pubkey[0]), y: u256_to_scalar(&pubkey[1]) })
    }

    /// Check whether the given Merkle root is a valid historical root
    #[instrument(skip_all, err, fields(root = %root))]
    pub async fn check_merkle_root_valid(
        &self,
        root: MerkleRoot,
    ) -> Result<bool, ArbitrumClientError> {
        self.get_darkpool_client()
            .root_in_history(scalar_to_u256(&root))
            .call()
            .await
            .map_err(|e| ArbitrumClientError::ContractInteraction(e.to_string()))
    }

    /// Check whether the given nullifier is used
    ///
    /// Returns `true` if the nullifier is used, `false` otherwise
    #[instrument(skip_all, err, fields(nullifier = %nullifier))]
    pub async fn check_nullifier_used(
        &self,
        nullifier: Nullifier,
    ) -> Result<bool, ArbitrumClientError> {
        self.get_darkpool_client()
            .is_nullifier_spent(scalar_to_u256(&nullifier))
            .call()
            .await
            .map_err(|e| ArbitrumClientError::ContractInteraction(e.to_string()))
    }

    /// Check whether the given public blinder is used
    ///
    /// Returns `true` if the blinder is used, `false` otherwise
    #[instrument(skip_all, err, fields(blinder = %blinder))]
    pub async fn is_public_blinder_used(
        &self,
        blinder: Scalar,
    ) -> Result<bool, ArbitrumClientError> {
        let blinder_u256 = scalar_to_u256(&blinder);
        self.get_darkpool_client()
            .is_public_blinder_used(blinder_u256)
            .call()
            .await
            .map_err(err_str!(ArbitrumClientError::ContractInteraction))
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
    ) -> Result<(), ArbitrumClientError> {
        let GenericValidWalletCreateBundle { statement, proof } = valid_wallet_create;

        let contract_proof = to_contract_proof(proof)?;
        let proof_calldata = serialize_calldata(&contract_proof)?;

        let contract_statement = to_contract_valid_wallet_create_statement(statement);
        let valid_wallet_create_statement_calldata = serialize_calldata(&contract_statement)?;

        let receipt = self
            .send_tx(
                self.get_darkpool_client()
                    .new_wallet(proof_calldata, valid_wallet_create_statement_calldata),
            )
            .await?;

        let tx_hash = format!("{:#x}", receipt.transaction_hash);
        backfill_trace_field("tx_hash", &tx_hash);
        info!("`new_wallet` tx hash: {}", tx_hash);

        Ok(())
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
    ) -> Result<(), ArbitrumClientError> {
        let GenericValidWalletUpdateBundle { statement, proof } = valid_wallet_update;

        let contract_proof = to_contract_proof(proof)?;
        let proof_calldata = serialize_calldata(&contract_proof)?;

        let contract_statement = to_contract_valid_wallet_update_statement(statement)?;
        let valid_wallet_update_statement_calldata = serialize_calldata(&contract_statement)?;

        let contract_transfer_aux_data =
            transfer_auth.map(to_contract_transfer_aux_data).transpose()?.unwrap_or_default();
        let transfer_aux_data_calldata = serialize_calldata(&contract_transfer_aux_data)?;

        let receipt = self
            .send_tx(self.get_darkpool_client().update_wallet(
                proof_calldata,
                valid_wallet_update_statement_calldata,
                wallet_commitment_signature.into(),
                transfer_aux_data_calldata,
            ))
            .await?;

        let tx_hash = format!("{:#x}", receipt.transaction_hash);
        backfill_trace_field("tx_hash", &tx_hash);
        info!("`update_wallet` tx hash: {}", tx_hash);

        Ok(())
    }

    /// Call the `process_match_settle` contract method with the given
    /// match payloads and `VALID MATCH SETTLE` statement
    ///
    /// Awaits until the transaction is confirmed on-chain
    #[instrument(skip_all, err, fields(
        tx_hash,
        party0_blinder = %match_bundle.match_proof.statement.party0_modified_shares.blinder,
        party1_blinder = %match_bundle.match_proof.statement.party1_modified_shares.blinder
    ))]
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
        let receipt = self
            .send_tx(self.get_darkpool_client().process_match_settle(
                party_0_match_payload_calldata,
                party_1_match_payload_calldata,
                valid_match_settle_statement_calldata,
                match_proofs_calldata,
                match_link_proofs_calldata,
            ))
            .await?;

        let tx_hash = format!("{:#x}", receipt.transaction_hash);
        backfill_trace_field("tx_hash", &tx_hash);
        info!("`process_match_settle` tx hash: {}", tx_hash);

        Ok(())
    }

    /// Return the tx parameters for a `process_atomic_match_settle` call
    ///
    /// We do not submit the transaction here, as atomic matches are settled by
    /// the external party
    pub fn gen_atomic_match_settle_calldata(
        &self,
        receiver_address: Option<Address>,
        internal_party_validity_proofs: &OrderValidityProofBundle,
        match_atomic_bundle: &AtomicMatchSettleBundle,
    ) -> Result<TypedTransaction, ArbitrumClientError> {
        // Destructure proof bundles
        let GenericMatchSettleAtomicBundle {
            statement: valid_match_settle_atomic_statement,
            proof: valid_match_settle_atomic_proof,
        } = match_atomic_bundle.copy_atomic_match_proof();

        let internal_party_valid_commitments_statement =
            internal_party_validity_proofs.commitment_proof.statement;
        let internal_party_valid_reblind_statement =
            internal_party_validity_proofs.reblind_proof.statement.clone();

        let internal_party_match_payload = MatchPayload {
            valid_commitments_statement: to_contract_valid_commitments_statement(
                internal_party_valid_commitments_statement,
            ),
            valid_reblind_statement: to_contract_valid_reblind_statement(
                &internal_party_valid_reblind_statement,
            ),
        };

        let match_proofs = build_atomic_match_proofs(
            internal_party_validity_proofs,
            &valid_match_settle_atomic_proof,
        )
        .map_err(ArbitrumClientError::Conversion)?;

        let match_link_proofs =
            build_atomic_match_linking_proofs(internal_party_validity_proofs, match_atomic_bundle)
                .map_err(ArbitrumClientError::Conversion)?;

        // Serialize calldata
        let internal_party_match_payload_calldata =
            serialize_calldata(&internal_party_match_payload)?;

        let contract_valid_match_settle_atomic_statement =
            to_contract_valid_match_settle_atomic_statement(&valid_match_settle_atomic_statement)?;
        let valid_match_settle_atomic_statement_calldata =
            serialize_calldata(&contract_valid_match_settle_atomic_statement)?;

        let match_proofs_calldata = serialize_calldata(&match_proofs)?;
        let match_link_proofs_calldata = serialize_calldata(&match_link_proofs)?;

        // Generate the calldata for `process_atomic_match_settle`
        Ok(self.build_atomic_match_from_serialized_data(
            receiver_address,
            internal_party_match_payload_calldata,
            valid_match_settle_atomic_statement_calldata,
            match_proofs_calldata,
            match_link_proofs_calldata,
        ))
    }

    /// Build `process_atomic_match_settle` from calldata serialized values
    fn build_atomic_match_from_serialized_data(
        &self,
        receiver: Option<Address>,
        internal_party_match_payload_calldata: Bytes,
        valid_match_settle_atomic_statement_calldata: Bytes,
        match_proofs_calldata: Bytes,
        match_link_proofs_calldata: Bytes,
    ) -> TypedTransaction {
        if let Some(receiver) = receiver {
            self.get_darkpool_client()
                .process_atomic_match_settle_with_receiver(
                    receiver,
                    internal_party_match_payload_calldata,
                    valid_match_settle_atomic_statement_calldata,
                    match_proofs_calldata,
                    match_link_proofs_calldata,
                )
                .tx
        } else {
            self.get_darkpool_client()
                .process_atomic_match_settle(
                    internal_party_match_payload_calldata,
                    valid_match_settle_atomic_statement_calldata,
                    match_proofs_calldata,
                    match_link_proofs_calldata,
                )
                .tx
        }
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
    ) -> Result<(), ArbitrumClientError> {
        let GenericRelayerFeeSettlementBundle { statement, proof } = valid_relayer_fee_settlement;

        let contract_proof = to_contract_proof(proof)?;
        let proof_calldata = serialize_calldata(&contract_proof)?;

        let contract_statement = to_contract_valid_relayer_fee_settlement_statement(statement)?;
        let valid_relayer_fee_settlement_statement_calldata =
            serialize_calldata(&contract_statement)?;

        let receipt = self
            .send_tx(self.get_darkpool_client().settle_online_relayer_fee(
                proof_calldata,
                valid_relayer_fee_settlement_statement_calldata,
                relayer_wallet_commitment_signature.into(),
            ))
            .await?;

        let tx_hash = format!("{:#x}", receipt.transaction_hash);
        backfill_trace_field("tx_hash", &tx_hash);
        info!("`settle_online_relayer_fee` tx hash: {}", tx_hash);

        Ok(())
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
    ) -> Result<(), ArbitrumClientError> {
        let GenericOfflineFeeSettlementBundle { statement, proof } = valid_offline_fee_settlement;

        let contract_proof = to_contract_proof(proof)?;
        let proof_calldata = serialize_calldata(&contract_proof)?;

        let contract_statement = to_contract_valid_offline_fee_settlement_statement(statement);
        let valid_offline_fee_settlement_statement_calldata =
            serialize_calldata(&contract_statement)?;

        let receipt = self
            .send_tx(self.get_darkpool_client().settle_offline_fee(
                proof_calldata,
                valid_offline_fee_settlement_statement_calldata,
            ))
            .await?;

        let tx_hash = format!("{:#x}", receipt.transaction_hash);
        backfill_trace_field("tx_hash", &tx_hash);
        info!("`settle_offline_fee` tx hash: {}", tx_hash);

        Ok(())
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
    ) -> Result<(), ArbitrumClientError> {
        let GenericFeeRedemptionBundle { statement, proof } = valid_fee_redemption;

        let contract_proof = to_contract_proof(proof)?;
        let proof_calldata = serialize_calldata(&contract_proof)?;

        let contract_statement = to_contract_valid_fee_redemption_statement(statement)?;
        let valid_fee_redemption_statement_calldata = serialize_calldata(&contract_statement)?;

        let receipt = self
            .send_tx(self.get_darkpool_client().redeem_fee(
                proof_calldata,
                valid_fee_redemption_statement_calldata,
                recipient_wallet_commitment_signature.into(),
            ))
            .await?;

        let tx_hash = format!("{:#x}", receipt.transaction_hash);
        backfill_trace_field("tx_hash", &tx_hash);
        info!("`redeem_fee` tx hash: {}", tx_hash);

        Ok(())
    }

    // -----------
    // | HELPERS |
    // -----------

    /// Sends a transaction, awaiting its confirmation and returning the receipt
    pub async fn send_tx(
        &self,
        tx: ContractCall<MiddlewareStack, impl Detokenize>,
    ) -> Result<TransactionReceipt, ArbitrumClientError> {
        #[cfg(feature = "tx-metrics")]
        incr_inflight_txs();

        // Set the gas price to 2x the latest basefee for simplicity
        let latest_block = self
            .client()
            .get_block(BlockNumber::Latest)
            .await
            .map_err(err_str!(ArbitrumClientError::Rpc))?
            .ok_or(ArbitrumClientError::Rpc("No latest block found".to_string()))?;

        let latest_basefee = latest_block
            .base_fee_per_gas
            .ok_or(ArbitrumClientError::Rpc("No basefee found".to_string()))?;

        let tx = tx.gas_price(latest_basefee * 2);

        let receipt = tx
            .send()
            .await
            .map_err(|e| ArbitrumClientError::ContractInteraction(e.to_string()))?
            .await
            .map_err(|e| ArbitrumClientError::ContractInteraction(e.to_string()))?
            .ok_or(ArbitrumClientError::TxDropped)?;

        #[cfg(feature = "tx-metrics")]
        decr_inflight_txs();

        // Check for failure
        let status = receipt.status.expect("status is `Some` after EIP-658");
        if status.is_zero() {
            let error_msg = format!("tx ({:#x}) failed with status 0", receipt.transaction_hash);
            return Err(ArbitrumClientError::ContractInteraction(error_msg));
        }

        Ok(receipt)
    }
}
