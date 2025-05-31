//! The Base implementation of the darkpool client
pub mod conversion;
mod helpers;

use alloy::{
    consensus::constants::SELECTOR_LEN,
    rpc::types::{TransactionReceipt, TransactionRequest},
};
use alloy_primitives::{Address, Bytes, Selector};
use alloy_sol_types::SolCall;
use async_trait::async_trait;
use circuit_types::{
    elgamal::EncryptionKey, fixed_point::FixedPoint, merkle::MerkleRoot,
    r#match::ExternalMatchResult, wallet::Nullifier, SizedWalletShare,
};
use common::types::{
    proof_bundles::{
        AtomicMatchSettleBundle, MalleableAtomicMatchSettleBundle, MatchBundle,
        OrderValidityProofBundle, SizedFeeRedemptionBundle, SizedOfflineFeeSettlementBundle,
        SizedRelayerFeeSettlementBundle, SizedValidWalletCreateBundle,
        SizedValidWalletUpdateBundle,
    },
    transfer_auth::TransferAuth,
};
use constants::Scalar;
use conversion::{ToCircuitType, ToContractType};
use helpers::{
    parse_shares_from_new_wallet, parse_shares_from_process_atomic_match_settle,
    parse_shares_from_process_malleable_atomic_match_settle,
    parse_shares_from_process_match_settle, parse_shares_from_redeem_fee,
    parse_shares_from_settle_offline_fee, parse_shares_from_update_wallet,
};
use renegade_solidity_abi::IDarkpool::{
    createWalletCall, processAtomicMatchSettleCall, processMalleableAtomicMatchSettleCall,
    processMatchSettleCall, redeemFeeCall, settleOfflineFeeCall, updateWalletCall,
    IDarkpoolInstance, MalleableMatchAtomicProofs, MatchAtomicLinkingProofs, MatchAtomicProofs,
    MatchLinkingProofs, MatchProofs, MerkleInsertion as AbiMerkleInsertion,
    MerkleOpeningNode as AbiMerkleOpeningNode, NullifierSpent as AbiNullifierSpent,
    WalletUpdated as AbiWalletUpdated,
};
use tracing::error;

use crate::{
    client::RenegadeProvider,
    conversion::{amount_to_u256, scalar_to_u256, u256_to_amount, u256_to_scalar},
    errors::DarkpoolClientError,
    traits::{
        DarkpoolImpl, DarkpoolImplExt, MerkleInsertionEvent, MerkleOpeningNodeEvent,
        NullifierSpentEvent, WalletUpdatedEvent,
    },
};

/// The set of known selectors for the Base darkpool
const KNOWN_SELECTORS: [[u8; SELECTOR_LEN]; 7] = [
    createWalletCall::SELECTOR,
    updateWalletCall::SELECTOR,
    processMatchSettleCall::SELECTOR,
    processAtomicMatchSettleCall::SELECTOR,
    processMalleableAtomicMatchSettleCall::SELECTOR,
    settleOfflineFeeCall::SELECTOR,
    redeemFeeCall::SELECTOR,
];

/// The Base darkpool implementation
#[derive(Clone)]
pub struct BaseDarkpool {
    /// The darkpool instance
    darkpool: IDarkpoolInstance<RenegadeProvider>,
}

impl BaseDarkpool {
    /// Get a reference to the darkpool instance
    pub fn darkpool(&self) -> &IDarkpoolInstance<RenegadeProvider> {
        &self.darkpool
    }
}

#[async_trait]
impl DarkpoolImpl for BaseDarkpool {
    type MerkleInsertion = AbiMerkleInsertion;
    type MerkleOpening = AbiMerkleOpeningNode;
    type NullifierSpent = AbiNullifierSpent;
    type WalletUpdated = AbiWalletUpdated;

    fn new(darkpool_addr: Address, provider: RenegadeProvider) -> Self {
        Self { darkpool: IDarkpoolInstance::new(darkpool_addr, provider) }
    }

    fn address(&self) -> Address {
        *self.darkpool.address()
    }

    fn provider(&self) -> &RenegadeProvider {
        self.darkpool.provider()
    }

    // -----------
    // | Getters |
    // -----------

    async fn get_merkle_root(&self) -> Result<Scalar, DarkpoolClientError> {
        self.darkpool
            .getMerkleRoot()
            .call()
            .await
            .map_err(DarkpoolClientError::contract_interaction)
            .map(u256_to_scalar)
    }

    async fn get_protocol_fee(&self) -> Result<FixedPoint, DarkpoolClientError> {
        self.darkpool
            .getProtocolFee()
            .call()
            .await
            .map_err(DarkpoolClientError::contract_interaction)
            .map(|r| FixedPoint::from_repr(u256_to_scalar(r)))
    }

    async fn get_external_match_fee(
        &self,
        mint: Address,
    ) -> Result<FixedPoint, DarkpoolClientError> {
        self.darkpool
            .getTokenExternalMatchFeeRate(mint)
            .call()
            .await
            .map_err(DarkpoolClientError::contract_interaction)
            .map(|r| FixedPoint::from_repr(u256_to_scalar(r)))
    }

    async fn get_protocol_pubkey(&self) -> Result<EncryptionKey, DarkpoolClientError> {
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

    async fn check_merkle_root(&self, root: MerkleRoot) -> Result<bool, DarkpoolClientError> {
        let root_u256 = scalar_to_u256(root);
        self.darkpool()
            .rootInHistory(root_u256)
            .call()
            .await
            .map_err(DarkpoolClientError::contract_interaction)
    }

    async fn is_nullifier_spent(&self, nullifier: Nullifier) -> Result<bool, DarkpoolClientError> {
        let nullifier_u256 = scalar_to_u256(nullifier);
        self.darkpool()
            .nullifierSpent(nullifier_u256)
            .call()
            .await
            .map_err(DarkpoolClientError::contract_interaction)
    }

    async fn is_blinder_used(&self, blinder: Scalar) -> Result<bool, DarkpoolClientError> {
        let blinder_u256 = scalar_to_u256(blinder);
        self.darkpool()
            .publicBlinderUsed(blinder_u256)
            .call()
            .await
            .map_err(DarkpoolClientError::contract_interaction)
    }

    fn is_known_selector(selector: Selector) -> bool {
        KNOWN_SELECTORS.contains(&selector.0)
    }

    // -----------
    // | Setters |
    // -----------

    async fn new_wallet(
        &self,
        valid_wallet_create: &SizedValidWalletCreateBundle,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        let statement = valid_wallet_create.statement.to_contract_type()?;
        let proof = valid_wallet_create.proof.to_contract_type()?;
        let call = self.darkpool.createWallet(statement, proof);
        self.send_tx(call).await
    }

    async fn update_wallet(
        &self,
        valid_wallet_update: &SizedValidWalletUpdateBundle,
        wallet_commitment_signature: Vec<u8>,
        transfer_auth: Option<TransferAuth>,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        // TODO: re-serialize the signature using the ABI encoding
        let statement = valid_wallet_update.statement.to_contract_type()?;
        let proof = valid_wallet_update.proof.to_contract_type()?;
        let transfer_auth = match transfer_auth {
            Some(transfer_auth) => transfer_auth.to_contract_type()?,
            None => Default::default(),
        };

        let call = self.darkpool.updateWallet(
            Bytes::from(wallet_commitment_signature),
            transfer_auth,
            statement,
            proof,
        );

        self.send_tx(call).await
    }

    async fn process_match_settle(
        &self,
        party0_validity: &OrderValidityProofBundle,
        party1_validity: &OrderValidityProofBundle,
        match_bundle: &MatchBundle,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        let party0_payload = party0_validity.to_contract_type()?;
        let party1_payload = party1_validity.to_contract_type()?;
        let statement = match_bundle.match_proof.statement.to_contract_type()?;

        // Build the match proof bundle
        let commitments0 = party0_validity.commitment_proof.proof.to_contract_type()?;
        let reblind0 = party0_validity.reblind_proof.proof.to_contract_type()?;
        let commitments1 = party1_validity.commitment_proof.proof.to_contract_type()?;
        let reblind1 = party1_validity.reblind_proof.proof.to_contract_type()?;
        let match_proof = match_bundle.match_proof.proof.to_contract_type()?;
        let proofs = MatchProofs {
            validCommitments0: commitments0,
            validReblind0: reblind0,
            validCommitments1: commitments1,
            validReblind1: reblind1,
            validMatchSettle: match_proof,
        };

        // Build the link proofs bundle
        let commitments_reblind0 = party0_validity.linking_proof.to_contract_type()?;
        let commitments_match0 = match_bundle.commitments_link0.to_contract_type()?;
        let commitments_reblind1 = party1_validity.linking_proof.to_contract_type()?;
        let commitments_match1 = match_bundle.commitments_link1.to_contract_type()?;
        let link_proofs = MatchLinkingProofs {
            validReblindCommitments0: commitments_reblind0,
            validCommitmentsMatchSettle0: commitments_match0,
            validReblindCommitments1: commitments_reblind1,
            validCommitmentsMatchSettle1: commitments_match1,
        };

        // Submit the match settle tx
        let call = self.darkpool.processMatchSettle(
            party0_payload,
            party1_payload,
            statement,
            proofs,
            link_proofs,
        );
        self.send_tx(call).await
    }

    // This method is unused in the relayer and not supported on Base
    async fn settle_online_relayer_fee(
        &self,
        _: &SizedRelayerFeeSettlementBundle,
        _: Vec<u8>,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        unimplemented!("`settle_online_relayer_fee` is not supported on Base")
    }

    async fn settle_offline_fee(
        &self,
        valid_offline_fee_settlement: &SizedOfflineFeeSettlementBundle,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        let statement = valid_offline_fee_settlement.statement.to_contract_type()?;
        let proof = valid_offline_fee_settlement.proof.to_contract_type()?;
        let call = self.darkpool.settleOfflineFee(statement, proof);
        self.send_tx(call).await
    }

    async fn redeem_fee(
        &self,
        valid_fee_redemption: &SizedFeeRedemptionBundle,
        recipient_wallet_commitment_signature: Vec<u8>,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        // TODO: re-serialize the signature using the ABI encoding
        let statement = valid_fee_redemption.statement.to_contract_type()?;
        let proof = valid_fee_redemption.proof.to_contract_type()?;
        let call = self.darkpool.redeemFee(
            Bytes::from(recipient_wallet_commitment_signature),
            statement,
            proof,
        );
        self.send_tx(call).await
    }

    // ----------------
    // | Calldata Gen |
    // ----------------

    fn gen_atomic_match_settle_calldata(
        &self,
        receiver_address: Option<Address>,
        validity_proofs: &OrderValidityProofBundle,
        match_atomic_bundle: &AtomicMatchSettleBundle,
    ) -> Result<TransactionRequest, DarkpoolClientError> {
        let internal_party_payload = validity_proofs.to_contract_type()?;
        let statement = match_atomic_bundle.atomic_match_proof.statement.to_contract_type()?;

        // Build the match proofs bundle
        let commitments_proof = validity_proofs.commitment_proof.proof.to_contract_type()?;
        let reblind_proof = validity_proofs.reblind_proof.proof.to_contract_type()?;
        let match_proof = match_atomic_bundle.atomic_match_proof.proof.to_contract_type()?;
        let match_proofs = MatchAtomicProofs {
            validCommitments: commitments_proof,
            validReblind: reblind_proof,
            validMatchSettleAtomic: match_proof,
        };

        // Build the link proofs bundle
        let link_proofs = MatchAtomicLinkingProofs {
            validReblindCommitments: validity_proofs.linking_proof.to_contract_type()?,
            validCommitmentsMatchSettleAtomic: match_atomic_bundle
                .commitments_link
                .to_contract_type()?,
        };

        let receiver = receiver_address.unwrap_or_default();
        let req = self
            .darkpool
            .processAtomicMatchSettle(
                receiver,
                internal_party_payload,
                statement,
                match_proofs,
                link_proofs,
            )
            .into_transaction_request();

        Ok(req)
    }

    fn gen_malleable_atomic_match_settle_calldata(
        &self,
        receiver_address: Option<Address>,
        validity_proofs: &OrderValidityProofBundle,
        match_atomic_bundle: &MalleableAtomicMatchSettleBundle,
    ) -> Result<TransactionRequest, DarkpoolClientError> {
        let internal_party_payload = validity_proofs.to_contract_type()?;
        let statement = match_atomic_bundle.atomic_match_proof.statement.to_contract_type()?;

        // Build the match proofs bundle
        let commitments_proof = validity_proofs.commitment_proof.proof.to_contract_type()?;
        let reblind_proof = validity_proofs.reblind_proof.proof.to_contract_type()?;
        let match_proof = match_atomic_bundle.atomic_match_proof.proof.to_contract_type()?;
        let match_proofs = MalleableMatchAtomicProofs {
            validCommitments: commitments_proof,
            validReblind: reblind_proof,
            validMalleableMatchSettleAtomic: match_proof,
        };

        let link_proofs = MatchAtomicLinkingProofs {
            validReblindCommitments: validity_proofs.linking_proof.to_contract_type()?,
            validCommitmentsMatchSettleAtomic: match_atomic_bundle
                .commitments_link
                .to_contract_type()?,
        };

        // Compute the quote and base amounts, defaulting to the max tradable amounts
        let match_res = &match_atomic_bundle.atomic_match_proof.statement.bounded_match_result;
        let price = match_res.price;
        let base_amount = match_res.max_base_amount;
        let base_amount_calldata = amount_to_u256(base_amount)?;

        let quote_amount_fp = price * Scalar::from(base_amount);
        let quote_amount_calldata = scalar_to_u256(quote_amount_fp.floor());

        let receiver = receiver_address.unwrap_or_default();
        let req = self
            .darkpool
            .processMalleableAtomicMatchSettle(
                quote_amount_calldata,
                base_amount_calldata,
                receiver,
                internal_party_payload,
                statement,
                match_proofs,
                link_proofs,
            )
            .into_transaction_request();

        Ok(req)
    }

    fn parse_shares(
        selector: Selector,
        calldata: &[u8],
        public_blinder_share: Scalar,
    ) -> Result<SizedWalletShare, DarkpoolClientError> {
        match selector.0 {
            createWalletCall::SELECTOR => parse_shares_from_new_wallet(calldata),
            updateWalletCall::SELECTOR => parse_shares_from_update_wallet(calldata),
            processMatchSettleCall::SELECTOR => {
                parse_shares_from_process_match_settle(calldata, public_blinder_share)
            },
            processAtomicMatchSettleCall::SELECTOR => {
                parse_shares_from_process_atomic_match_settle(calldata)
            },
            processMalleableAtomicMatchSettleCall::SELECTOR => {
                parse_shares_from_process_malleable_atomic_match_settle(calldata)
            },
            settleOfflineFeeCall::SELECTOR => parse_shares_from_settle_offline_fee(calldata),
            redeemFeeCall::SELECTOR => parse_shares_from_redeem_fee(calldata),
            _ => {
                error!("invalid selector when parsing public shares: {selector:?}");
                Err(DarkpoolClientError::InvalidSelector)
            },
        }
    }

    fn parse_external_match(
        calldata: &[u8],
    ) -> Result<Option<ExternalMatchResult>, DarkpoolClientError> {
        let selector = calldata[..SELECTOR_LEN].try_into().unwrap();
        let match_res = match selector {
            processAtomicMatchSettleCall::SELECTOR => {
                let call = processAtomicMatchSettleCall::abi_decode(calldata)?;
                call.matchSettleStatement.matchResult.to_circuit_type()?
            },
            processMalleableAtomicMatchSettleCall::SELECTOR => {
                let call = processMalleableAtomicMatchSettleCall::abi_decode(calldata)?;
                let bounded_res = call.matchSettleStatement.matchResult.to_circuit_type()?;
                let base_amount = u256_to_amount(call.baseAmount)?;
                bounded_res.to_external_match_result(base_amount)
            },
            _ => return Ok(None),
        };

        Ok(Some(match_res))
    }

    #[cfg(feature = "integration")]
    async fn clear_merkle_tree(&self) -> Result<TransactionReceipt, DarkpoolClientError> {
        unimplemented!("We don't currently integration test the Base client")
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
    fn depth(&self) -> u64 {
        self.depth as u64
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
