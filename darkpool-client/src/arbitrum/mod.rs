//! Arbitrum implementation of the darkpool client

pub mod abi;
pub mod contract_types;
pub mod helpers;

use crate::{
    client::RenegadeProvider,
    conversion::{scalar_to_u256, u256_to_amount, u256_to_scalar},
    errors::DarkpoolClientError,
    traits::{
        DarkpoolImpl, DarkpoolImplExt, MerkleInsertionEvent, MerkleOpeningNodeEvent,
        NullifierSpentEvent, WalletUpdatedEvent,
    },
};
use abi::{
    Darkpool::{
        DarkpoolInstance, MerkleInsertion as AbiMerkleInsertion,
        MerkleOpeningNode as AbiMerkleOpeningNode, NullifierSpent as AbiNullifierSpent,
        WalletUpdated as AbiWalletUpdated, newWalletCall, processAtomicMatchSettleCall,
        processAtomicMatchSettleWithReceiverCall, processMalleableAtomicMatchSettleCall,
        processMalleableAtomicMatchSettleWithReceiverCall, processMatchSettleCall, redeemFeeCall,
        settleOfflineFeeCall, settleOnlineRelayerFeeCall, updateWalletCall,
    },
    KNOWN_SELECTORS, PROCESS_ATOMIC_MATCH_SETTLE_SELECTOR,
    PROCESS_ATOMIC_MATCH_SETTLE_WITH_RECEIVER_SELECTOR,
    PROCESS_MALLEABLE_ATOMIC_MATCH_SETTLE_SELECTOR,
    PROCESS_MALLEABLE_ATOMIC_MATCH_SETTLE_WITH_RECEIVER_SELECTOR,
};
use alloy::{
    consensus::constants::SELECTOR_LEN,
    rpc::types::{TransactionReceipt, TransactionRequest},
};
use alloy_primitives::{Address, Bytes, Selector, U256};
use alloy_sol_types::SolCall;
use async_trait::async_trait;
use circuit_types::{
    SizedWalletShare, elgamal::EncryptionKey, fixed_point::FixedPoint,
    r#match::ExternalMatchResult, merkle::MerkleRoot, wallet::Nullifier,
};
use common::types::{
    proof_bundles::{
        GenericFeeRedemptionBundle, GenericOfflineFeeSettlementBundle,
        GenericRelayerFeeSettlementBundle, GenericValidWalletCreateBundle,
        GenericValidWalletUpdateBundle, OrderValidityProofBundle, SizedFeeRedemptionBundle,
        SizedOfflineFeeSettlementBundle, SizedRelayerFeeSettlementBundle,
        SizedValidWalletCreateBundle, SizedValidWalletUpdateBundle,
        ValidMalleableMatchSettleAtomicBundle, ValidMatchSettleAtomicBundle,
        ValidMatchSettleBundle,
    },
    transfer_auth::TransferAuth,
};
use constants::Scalar;
use contract_types::{
    MatchPayload, ValidMalleableMatchSettleAtomicStatement, ValidMatchSettleAtomicStatement,
    conversion::{
        build_atomic_match_linking_proofs, build_atomic_match_proofs, build_match_linking_proofs,
        build_match_proofs, to_circuit_bounded_match_result, to_circuit_external_match_result,
        to_contract_proof, to_contract_transfer_aux_data, to_contract_valid_commitments_statement,
        to_contract_valid_fee_redemption_statement,
        to_contract_valid_malleable_match_settle_atomic_statement,
        to_contract_valid_match_settle_atomic_statement, to_contract_valid_match_settle_statement,
        to_contract_valid_offline_fee_settlement_statement, to_contract_valid_reblind_statement,
        to_contract_valid_relayer_fee_settlement_statement,
        to_contract_valid_wallet_create_statement, to_contract_valid_wallet_update_statement,
    },
};
use helpers::{
    deserialize_calldata, parse_shares_from_new_wallet,
    parse_shares_from_process_atomic_match_settle,
    parse_shares_from_process_atomic_match_settle_with_receiver,
    parse_shares_from_process_malleable_atomic_match_settle,
    parse_shares_from_process_malleable_atomic_match_settle_with_receiver,
    parse_shares_from_process_match_settle, parse_shares_from_redeem_fee,
    parse_shares_from_settle_offline_fee, parse_shares_from_settle_online_relayer_fee,
    parse_shares_from_update_wallet, serialize_calldata,
};
use tracing::error;

/// The Arbitrum implementation of the darkpool
#[derive(Clone)]
pub struct ArbitrumDarkpool {
    /// The darkpool instance
    darkpool: DarkpoolInstance<RenegadeProvider>,
}

impl ArbitrumDarkpool {
    /// Get a reference to the darkpool instance
    pub fn darkpool(&self) -> &DarkpoolInstance<RenegadeProvider> {
        &self.darkpool
    }
}

#[async_trait]
impl DarkpoolImpl for ArbitrumDarkpool {
    type MerkleInsertion = AbiMerkleInsertion;
    type MerkleOpening = AbiMerkleOpeningNode;
    type NullifierSpent = AbiNullifierSpent;
    type WalletUpdated = AbiWalletUpdated;

    /// Create a new darkpool implementation
    fn new(darkpool_addr: Address, provider: RenegadeProvider) -> Self {
        Self { darkpool: DarkpoolInstance::new(darkpool_addr, provider) }
    }

    /// Get the address of the darkpool contract
    fn address(&self) -> Address {
        *self.darkpool.address()
    }

    /// Get a reference to the provider
    fn provider(&self) -> &RenegadeProvider {
        self.darkpool.provider()
    }

    // -----------
    // | Getters |
    // -----------

    /// Get the current Merkle root in the contract
    async fn get_merkle_root(&self) -> Result<Scalar, DarkpoolClientError> {
        self.darkpool()
            .getRoot()
            .call()
            .await
            .map_err(DarkpoolClientError::contract_interaction)
            .map(u256_to_scalar)
    }

    /// Get the base fee charged by the contract
    async fn get_protocol_fee(&self) -> Result<FixedPoint, DarkpoolClientError> {
        self.darkpool()
            .getFee()
            .call()
            .await
            .map_err(DarkpoolClientError::contract_interaction)
            .map(|r| FixedPoint::from_repr(u256_to_scalar(r)))
    }

    /// Get the external match fee for the given mint
    async fn get_external_match_fee(
        &self,
        mint: Address,
    ) -> Result<FixedPoint, DarkpoolClientError> {
        self.darkpool()
            .getExternalMatchFeeForAsset(mint)
            .call()
            .await
            .map_err(DarkpoolClientError::contract_interaction)
            .map(|r| FixedPoint::from_repr(u256_to_scalar(r)))
    }

    /// Get the protocol pubkey
    async fn get_protocol_pubkey(&self) -> Result<EncryptionKey, DarkpoolClientError> {
        let pubkey = self
            .darkpool()
            .getPubkey()
            .call()
            .await
            .map_err(DarkpoolClientError::contract_interaction)?;

        Ok(EncryptionKey { x: u256_to_scalar(pubkey[0]), y: u256_to_scalar(pubkey[1]) })
    }

    /// Check whether a given root is in the contract's history
    async fn check_merkle_root(&self, root: MerkleRoot) -> Result<bool, DarkpoolClientError> {
        let root_u256 = scalar_to_u256(root);
        self.darkpool()
            .rootInHistory(root_u256)
            .call()
            .await
            .map_err(DarkpoolClientError::contract_interaction)
    }

    /// Check whether a given nullifier is used
    async fn is_nullifier_spent(&self, nullifier: Nullifier) -> Result<bool, DarkpoolClientError> {
        let nullifier_u256 = scalar_to_u256(nullifier);
        self.darkpool()
            .isNullifierSpent(nullifier_u256)
            .call()
            .await
            .map_err(DarkpoolClientError::contract_interaction)
    }

    /// Check whether a given blinder is used
    async fn is_blinder_used(&self, blinder: Scalar) -> Result<bool, DarkpoolClientError> {
        let blinder_u256 = scalar_to_u256(blinder);
        self.darkpool()
            .isPublicBlinderUsed(blinder_u256)
            .call()
            .await
            .map_err(DarkpoolClientError::contract_interaction)
    }

    /// Whether a given selector is known to the darkpool implementation
    fn is_known_selector(selector: Selector) -> bool {
        KNOWN_SELECTORS.contains(&selector)
    }

    // -----------
    // | Setters |
    // -----------

    /// Create a new wallet in the darkpool contract
    async fn new_wallet(
        &self,
        valid_wallet_create: &SizedValidWalletCreateBundle,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        let GenericValidWalletCreateBundle { statement, proof } = valid_wallet_create;

        let contract_proof = to_contract_proof(proof)?;
        let proof_calldata = serialize_calldata(&contract_proof)?;

        let contract_statement = to_contract_valid_wallet_create_statement(statement);
        let valid_wallet_create_statement_calldata = serialize_calldata(&contract_statement)?;

        let call =
            self.darkpool().newWallet(proof_calldata, valid_wallet_create_statement_calldata);
        self.send_tx(call).await
    }

    /// Update a wallet in the darkpool contract
    async fn update_wallet(
        &self,
        valid_wallet_update: &SizedValidWalletUpdateBundle,
        wallet_commitment_signature: Vec<u8>,
        transfer_auth: Option<TransferAuth>,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        let GenericValidWalletUpdateBundle { statement, proof } = valid_wallet_update;

        let contract_proof = to_contract_proof(proof)?;
        let proof_calldata = serialize_calldata(&contract_proof)?;

        let contract_statement = to_contract_valid_wallet_update_statement(statement)?;
        let valid_wallet_update_statement_calldata = serialize_calldata(&contract_statement)?;

        let contract_transfer_aux_data =
            transfer_auth.map(to_contract_transfer_aux_data).transpose()?.unwrap_or_default();
        let transfer_aux_data_calldata = serialize_calldata(&contract_transfer_aux_data)?;

        let call = self.darkpool().updateWallet(
            proof_calldata,
            valid_wallet_update_statement_calldata,
            wallet_commitment_signature.into(),
            transfer_aux_data_calldata,
        );
        self.send_tx(call).await
    }

    /// Process a match settle in the darkpool contract
    async fn process_match_settle(
        &self,
        party0_validity_proofs: &OrderValidityProofBundle,
        party1_validity_proofs: &OrderValidityProofBundle,
        match_bundle: ValidMatchSettleBundle,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        // Destructure proof bundles
        let valid_match_settle_statement = match_bundle.statement.clone();
        let valid_match_settle_proof = match_bundle.proof.clone();

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
        .map_err(DarkpoolClientError::Conversion)?;

        let match_link_proofs = build_match_linking_proofs(
            party0_validity_proofs,
            party1_validity_proofs,
            &match_bundle,
        )
        .map_err(DarkpoolClientError::Conversion)?;

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
        let call = self.darkpool().processMatchSettle(
            party_0_match_payload_calldata,
            party_1_match_payload_calldata,
            valid_match_settle_statement_calldata,
            match_proofs_calldata,
            match_link_proofs_calldata,
        );
        self.send_tx(call).await
    }

    /// Settle an online relayer fee in the darkpool contract
    async fn settle_online_relayer_fee(
        &self,
        valid_relayer_fee_settlement: &SizedRelayerFeeSettlementBundle,
        relayer_wallet_commitment_signature: Vec<u8>,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        let GenericRelayerFeeSettlementBundle { statement, proof } = valid_relayer_fee_settlement;

        let contract_proof = to_contract_proof(proof)?;
        let proof_calldata = serialize_calldata(&contract_proof)?;

        let contract_statement = to_contract_valid_relayer_fee_settlement_statement(statement)?;
        let valid_relayer_fee_settlement_statement_calldata =
            serialize_calldata(&contract_statement)?;

        let call = self.darkpool().settleOnlineRelayerFee(
            proof_calldata,
            valid_relayer_fee_settlement_statement_calldata,
            relayer_wallet_commitment_signature.into(),
        );
        self.send_tx(call).await
    }

    /// Settle an offline fee in the darkpool contract
    async fn settle_offline_fee(
        &self,
        valid_offline_fee_settlement: &SizedOfflineFeeSettlementBundle,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        let GenericOfflineFeeSettlementBundle { statement, proof } = valid_offline_fee_settlement;

        let contract_proof = to_contract_proof(proof)?;
        let proof_calldata = serialize_calldata(&contract_proof)?;

        let contract_statement = to_contract_valid_offline_fee_settlement_statement(statement);
        let valid_offline_fee_settlement_statement_calldata =
            serialize_calldata(&contract_statement)?;

        let call = self
            .darkpool()
            .settleOfflineFee(proof_calldata, valid_offline_fee_settlement_statement_calldata);
        self.send_tx(call).await
    }

    /// Redeem a fee in the darkpool contract
    async fn redeem_fee(
        &self,
        valid_fee_redemption: &SizedFeeRedemptionBundle,
        recipient_wallet_commitment_signature: Vec<u8>,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        let GenericFeeRedemptionBundle { statement, proof } = valid_fee_redemption;

        let contract_proof = to_contract_proof(proof)?;
        let proof_calldata = serialize_calldata(&contract_proof)?;

        let contract_statement = to_contract_valid_fee_redemption_statement(statement)?;
        let valid_fee_redemption_statement_calldata = serialize_calldata(&contract_statement)?;

        let call = self.darkpool().redeemFee(
            proof_calldata,
            valid_fee_redemption_statement_calldata,
            recipient_wallet_commitment_signature.into(),
        );
        self.send_tx(call).await
    }

    // ----------------
    // | Calldata Gen |
    // ----------------

    /// Generate calldata for a `processAtomicMatchSettle` call
    fn gen_atomic_match_settle_calldata(
        &self,
        receiver_address: Option<Address>,
        internal_party_validity_proofs: &OrderValidityProofBundle,
        match_atomic_bundle: ValidMatchSettleAtomicBundle,
    ) -> Result<TransactionRequest, DarkpoolClientError> {
        // Destructure proof bundles
        let valid_match_settle_atomic_statement = &match_atomic_bundle.statement;
        let valid_match_settle_atomic_proof = &match_atomic_bundle.proof;
        let commitments_link = &match_atomic_bundle.commitments_link;

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
            valid_match_settle_atomic_proof,
        )
        .map_err(DarkpoolClientError::Conversion)?;

        let match_link_proofs =
            build_atomic_match_linking_proofs(internal_party_validity_proofs, commitments_link)
                .map_err(DarkpoolClientError::Conversion)?;

        // Serialize calldata
        let internal_party_match_payload_calldata =
            serialize_calldata(&internal_party_match_payload)?;

        let contract_valid_match_settle_atomic_statement =
            to_contract_valid_match_settle_atomic_statement(valid_match_settle_atomic_statement)?;
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

    /// Generate calldata for a `processMalleableAtomicMatchSettle` call
    fn gen_malleable_atomic_match_settle_calldata(
        &self,
        receiver_address: Option<Address>,
        internal_party_validity_proofs: &OrderValidityProofBundle,
        match_atomic_bundle: ValidMalleableMatchSettleAtomicBundle,
    ) -> Result<TransactionRequest, DarkpoolClientError> {
        let valid_match_settle_atomic_statement = &match_atomic_bundle.statement;
        let valid_match_settle_atomic_proof = &match_atomic_bundle.proof;
        let commitments_link = &match_atomic_bundle.commitments_link;

        let commitments_statement = internal_party_validity_proofs.commitment_proof.statement;
        let reblind_statement = &internal_party_validity_proofs.reblind_proof.statement;

        let internal_party_match_payload = MatchPayload {
            valid_commitments_statement: to_contract_valid_commitments_statement(
                commitments_statement,
            ),
            valid_reblind_statement: to_contract_valid_reblind_statement(reblind_statement),
        };

        // We use the same types here as in the regular atomic match case, though the
        // proofs and statements here encode a different relation
        let match_proofs = build_atomic_match_proofs(
            internal_party_validity_proofs,
            valid_match_settle_atomic_proof,
        )
        .map_err(DarkpoolClientError::Conversion)?;

        let link_proofs =
            build_atomic_match_linking_proofs(internal_party_validity_proofs, commitments_link)
                .map_err(DarkpoolClientError::Conversion)?;

        // Serialize calldata
        let internal_party_match_payload_calldata =
            serialize_calldata(&internal_party_match_payload)?;
        let contract_valid_match_settle_atomic_statement =
            to_contract_valid_malleable_match_settle_atomic_statement(
                &valid_match_settle_atomic_statement,
            )?;
        let valid_match_settle_atomic_statement_calldata =
            serialize_calldata(&contract_valid_match_settle_atomic_statement)?;
        let match_proofs_calldata = serialize_calldata(&match_proofs)?;
        let match_link_proofs_calldata = serialize_calldata(&link_proofs)?;

        // Generate the calldata for `process_atomic_match_settle`, use the max amount
        // as a placeholder for the calldata base amount
        let base_amount = valid_match_settle_atomic_statement.bounded_match_result.max_base_amount;
        let base_amount_calldata = U256::from(base_amount);

        let price = valid_match_settle_atomic_statement.bounded_match_result.price;
        let quote_amount_fp = price * Scalar::from(base_amount);
        let quote_amount_calldata = scalar_to_u256(quote_amount_fp.floor());

        Ok(self.build_malleable_atomic_match_from_serialized_data(
            quote_amount_calldata,
            base_amount_calldata,
            receiver_address,
            internal_party_match_payload_calldata,
            valid_match_settle_atomic_statement_calldata,
            match_proofs_calldata,
            match_link_proofs_calldata,
        ))
    }

    /// Parse wallet shares from a given transaction's calldata and selector
    fn parse_shares(
        selector: Selector,
        calldata: &[u8],
        public_blinder_share: Scalar,
    ) -> Result<SizedWalletShare, DarkpoolClientError> {
        match selector.0 {
            <newWalletCall as SolCall>::SELECTOR => parse_shares_from_new_wallet(calldata),
            <updateWalletCall as SolCall>::SELECTOR => parse_shares_from_update_wallet(calldata),
            <processMatchSettleCall as SolCall>::SELECTOR => {
                parse_shares_from_process_match_settle(calldata, public_blinder_share)
            },
            <processAtomicMatchSettleCall as SolCall>::SELECTOR => {
                parse_shares_from_process_atomic_match_settle(calldata)
            },
            <processAtomicMatchSettleWithReceiverCall as SolCall>::SELECTOR => {
                parse_shares_from_process_atomic_match_settle_with_receiver(calldata)
            },
            <processMalleableAtomicMatchSettleCall as SolCall>::SELECTOR => {
                parse_shares_from_process_malleable_atomic_match_settle(calldata)
            },
            <processMalleableAtomicMatchSettleWithReceiverCall as SolCall>::SELECTOR => {
                parse_shares_from_process_malleable_atomic_match_settle_with_receiver(calldata)
            },
            <settleOnlineRelayerFeeCall as SolCall>::SELECTOR => {
                parse_shares_from_settle_online_relayer_fee(calldata, public_blinder_share)
            },
            <settleOfflineFeeCall as SolCall>::SELECTOR => {
                parse_shares_from_settle_offline_fee(calldata)
            },
            <redeemFeeCall as SolCall>::SELECTOR => parse_shares_from_redeem_fee(calldata),
            _ => {
                error!("invalid selector when parsing public shares: {selector:?}");
                Err(DarkpoolClientError::InvalidSelector)
            },
        }
    }

    /// Parse an external match from a given transaction's calldata
    fn parse_external_match(
        calldata: &[u8],
    ) -> Result<Option<ExternalMatchResult>, DarkpoolClientError> {
        let selector = calldata[..SELECTOR_LEN].try_into().unwrap();

        // Parse the `VALID MATCH SETTLE ATOMIC` statement from the calldata
        let match_res = match selector {
            PROCESS_ATOMIC_MATCH_SETTLE_SELECTOR => {
                let call = processAtomicMatchSettleCall::abi_decode(calldata)?;
                Self::parse_external_match_from_calldata(&call.valid_match_settle_atomic_statement)
            },
            PROCESS_ATOMIC_MATCH_SETTLE_WITH_RECEIVER_SELECTOR => {
                let call = processAtomicMatchSettleWithReceiverCall::abi_decode(calldata)?;
                Self::parse_external_match_from_calldata(&call.valid_match_settle_atomic_statement)
            },
            PROCESS_MALLEABLE_ATOMIC_MATCH_SETTLE_WITH_RECEIVER_SELECTOR => {
                let call = processMalleableAtomicMatchSettleWithReceiverCall::abi_decode(calldata)?;
                Self::parse_external_match_from_malleable(
                    call.base_amount,
                    &call.valid_match_settle_statement,
                )
            },
            PROCESS_MALLEABLE_ATOMIC_MATCH_SETTLE_SELECTOR => {
                let call = processMalleableAtomicMatchSettleCall::abi_decode(calldata)?;
                Self::parse_external_match_from_malleable(
                    call.base_amount,
                    &call.valid_match_settle_statement,
                )
            },
            _ => return Ok(None),
        }?;

        Ok(Some(match_res))
    }

    // -----------
    // | Testing |
    // -----------

    /// Clear the Merkle tree for testing
    #[cfg(feature = "integration")]
    async fn clear_merkle_tree(&self) -> Result<TransactionReceipt, DarkpoolClientError> {
        let call = self.darkpool().clearMerkle();
        self.send_tx(call).await
    }
}

// -----------
// | Helpers |
// -----------

impl ArbitrumDarkpool {
    // --- Build Transactions --- //

    /// Build a `process_atomic_match_settle` transaction from calldata
    /// serialized values
    fn build_atomic_match_from_serialized_data(
        &self,
        receiver: Option<Address>,
        internal_party_match_payload_calldata: Bytes,
        valid_match_settle_atomic_statement_calldata: Bytes,
        match_proofs_calldata: Bytes,
        match_link_proofs_calldata: Bytes,
    ) -> TransactionRequest {
        if let Some(receiver) = receiver {
            self.darkpool()
                .processAtomicMatchSettleWithReceiver(
                    receiver,
                    internal_party_match_payload_calldata,
                    valid_match_settle_atomic_statement_calldata,
                    match_proofs_calldata,
                    match_link_proofs_calldata,
                )
                .into_transaction_request()
        } else {
            self.darkpool()
                .processAtomicMatchSettle(
                    internal_party_match_payload_calldata,
                    valid_match_settle_atomic_statement_calldata,
                    match_proofs_calldata,
                    match_link_proofs_calldata,
                )
                .into_transaction_request()
        }
    }

    /// Build a `process_malleable_atomic_match_settle` transaction from
    /// calldata serialized values
    #[allow(clippy::too_many_arguments)]
    fn build_malleable_atomic_match_from_serialized_data(
        &self,
        quote_amount: U256,
        base_amount: U256,
        receiver: Option<Address>,
        internal_party_match_payload_calldata: Bytes,
        valid_match_settle_atomic_statement_calldata: Bytes,
        match_proofs_calldata: Bytes,
        match_link_proofs_calldata: Bytes,
    ) -> TransactionRequest {
        if let Some(receiver) = receiver {
            self.darkpool()
                .processMalleableAtomicMatchSettleWithReceiver(
                    quote_amount,
                    base_amount,
                    receiver,
                    internal_party_match_payload_calldata,
                    valid_match_settle_atomic_statement_calldata,
                    match_proofs_calldata,
                    match_link_proofs_calldata,
                )
                .into_transaction_request()
        } else {
            self.darkpool()
                .processMalleableAtomicMatchSettle(
                    quote_amount,
                    base_amount,
                    internal_party_match_payload_calldata,
                    valid_match_settle_atomic_statement_calldata,
                    match_proofs_calldata,
                    match_link_proofs_calldata,
                )
                .into_transaction_request()
        }
    }

    // --- Parse External Matches --- //

    /// Parse an external match from a `VALID MATCH SETTLE ATOMIC` statement
    /// serialized as calldata bytes
    fn parse_external_match_from_calldata(
        statement_bytes: &[u8],
    ) -> Result<ExternalMatchResult, DarkpoolClientError> {
        let statement: ValidMatchSettleAtomicStatement = deserialize_calldata(statement_bytes)?;
        let match_result = to_circuit_external_match_result(&statement.match_result)?;
        Ok(match_result)
    }

    /// Parse an external match from a `VALID MALLEABLE MATCH SETTLE ATOMIC`
    /// statement and the calldata of the `processMalleableAtomicMatchSettle`
    fn parse_external_match_from_malleable(
        base_amount: U256,
        statement_bytes: &[u8],
    ) -> Result<ExternalMatchResult, DarkpoolClientError> {
        let statement: ValidMalleableMatchSettleAtomicStatement =
            deserialize_calldata(statement_bytes)?;
        let match_result = to_circuit_bounded_match_result(&statement.match_result)?;
        let base_amt = u256_to_amount(base_amount)?;
        let external_match = match_result.to_external_match_result(base_amt);

        Ok(external_match)
    }
}

// ----------
// | Events |
// ----------

impl MerkleInsertionEvent for AbiMerkleInsertion {
    fn index(&self) -> u128 {
        self.index
    }

    fn value(&self) -> Scalar {
        u256_to_scalar(self.value)
    }
}

impl MerkleOpeningNodeEvent for AbiMerkleOpeningNode {
    // The stylus contracts use "height" to refer to "depth"
    fn depth(&self) -> u64 {
        self.height as u64
    }

    fn index(&self) -> u64 {
        self.index as u64
    }

    fn new_value(&self) -> Scalar {
        u256_to_scalar(self.new_value)
    }
}

impl NullifierSpentEvent for AbiNullifierSpent {
    fn nullifier(&self) -> Nullifier {
        u256_to_scalar(self.nullifier)
    }
}

impl WalletUpdatedEvent for AbiWalletUpdated {
    fn blinder_share(&self) -> Scalar {
        u256_to_scalar(self.wallet_blinder_share)
    }
}
