//! The Base implementation of the darkpool client
mod conversion;

use alloy::rpc::types::{TransactionReceipt, TransactionRequest};
use conversion::to_contract_type;
use renegade_solidity_abi::IDarkpool::{
    IDarkpoolInstance, MalleableMatchAtomicProofs, MatchAtomicLinkingProofs, MatchAtomicProofs,
    MatchLinkingProofs, MatchProofs, MerkleInsertion as AbiMerkleInsertion,
    MerkleOpeningNode as AbiMerkleOpeningNode, NullifierSpent as AbiNullifierSpent,
    ValidMalleableMatchSettleAtomicStatement, WalletUpdated as AbiWalletUpdated,
};

use alloy_primitives::{Address, Bytes, Selector, U256};
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

use crate::{
    client::RenegadeProvider,
    conversion::{scalar_to_u256, u256_to_scalar},
    errors::DarkpoolClientError,
    traits::{
        DarkpoolImpl, DarkpoolImplExt, MerkleInsertionEvent, MerkleOpeningNodeEvent,
        NullifierSpentEvent, WalletUpdatedEvent,
    },
};

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
        todo!()
    }

    // -----------
    // | Setters |
    // -----------

    async fn new_wallet(
        &self,
        valid_wallet_create: &SizedValidWalletCreateBundle,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        let statement = to_contract_type(valid_wallet_create.statement.clone());
        let proof = to_contract_type(valid_wallet_create.proof.clone());
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
        let statement = to_contract_type(valid_wallet_update.statement.clone());
        let proof = to_contract_type(valid_wallet_update.proof.clone());
        let transfer_auth = transfer_auth.map(to_contract_type).unwrap_or_default();

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
        party0_validity_proofs: &OrderValidityProofBundle,
        party1_validity_proofs: &OrderValidityProofBundle,
        match_bundle: &MatchBundle,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        let party0_payload = to_contract_type(party0_validity_proofs.clone());
        let party1_payload = to_contract_type(party1_validity_proofs.clone());
        let statement = to_contract_type(match_bundle.match_proof.statement.clone());

        // Build the match proof bundle
        let commitments0 = to_contract_type(party0_validity_proofs.commitment_proof.proof.clone());
        let reblind0 = to_contract_type(party0_validity_proofs.reblind_proof.proof.clone());
        let commitments1 = to_contract_type(party1_validity_proofs.commitment_proof.proof.clone());
        let reblind1 = to_contract_type(party1_validity_proofs.reblind_proof.proof.clone());
        let match_proof = to_contract_type(match_bundle.match_proof.proof.clone());
        let proofs = MatchProofs {
            validCommitments0: commitments0,
            validReblind0: reblind0,
            validCommitments1: commitments1,
            validReblind1: reblind1,
            validMatchSettle: match_proof,
        };

        // Build the link proofs bundle
        let commitments_reblind0 = to_contract_type(party0_validity_proofs.linking_proof.clone());
        let commitments_match0 = to_contract_type(match_bundle.commitments_link0.clone());
        let commitments_reblind1 = to_contract_type(party1_validity_proofs.linking_proof.clone());
        let commitments_match1 = to_contract_type(match_bundle.commitments_link1.clone());
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
        let statement = to_contract_type(valid_offline_fee_settlement.statement.clone());
        let proof = to_contract_type(valid_offline_fee_settlement.proof.clone());
        let call = self.darkpool.settleOfflineFee(statement, proof);
        self.send_tx(call).await
    }

    async fn redeem_fee(
        &self,
        valid_fee_redemption: &SizedFeeRedemptionBundle,
        recipient_wallet_commitment_signature: Vec<u8>,
    ) -> Result<TransactionReceipt, DarkpoolClientError> {
        // TODO: re-serialize the signature using the ABI encoding
        let statement = to_contract_type(valid_fee_redemption.statement.clone());
        let proof = to_contract_type(valid_fee_redemption.proof.clone());
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
        let internal_party_payload = to_contract_type(validity_proofs.clone());
        let statement = to_contract_type(match_atomic_bundle.atomic_match_proof.statement.clone());

        // Build the match proofs bundle
        let commitments_proof = to_contract_type(validity_proofs.commitment_proof.proof.clone());
        let reblind_proof = to_contract_type(validity_proofs.reblind_proof.proof.clone());
        let match_proof = to_contract_type(match_atomic_bundle.atomic_match_proof.proof.clone());
        let match_proofs = MatchAtomicProofs {
            validCommitments: commitments_proof,
            validReblind: reblind_proof,
            validMatchSettleAtomic: match_proof,
        };

        // Build the link proofs bundle
        let link_proofs = MatchAtomicLinkingProofs {
            validReblindCommitments: to_contract_type(validity_proofs.linking_proof.clone()),
            validCommitmentsMatchSettleAtomic: to_contract_type(
                match_atomic_bundle.commitments_link.clone(),
            ),
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
        let internal_party_payload = to_contract_type(validity_proofs.clone());
        let statement: ValidMalleableMatchSettleAtomicStatement =
            to_contract_type(match_atomic_bundle.atomic_match_proof.statement.clone());

        // Build the match proofs bundle
        let commitments_proof = to_contract_type(validity_proofs.commitment_proof.proof.clone());
        let reblind_proof = to_contract_type(validity_proofs.reblind_proof.proof.clone());
        let match_proof = to_contract_type(match_atomic_bundle.atomic_match_proof.proof.clone());
        let match_proofs = MalleableMatchAtomicProofs {
            validCommitments: commitments_proof,
            validReblind: reblind_proof,
            validMalleableMatchSettleAtomic: match_proof,
        };

        let link_proofs = MatchAtomicLinkingProofs {
            validReblindCommitments: to_contract_type(validity_proofs.linking_proof.clone()),
            validCommitmentsMatchSettleAtomic: to_contract_type(
                match_atomic_bundle.commitments_link.clone(),
            ),
        };

        let receiver = receiver_address.unwrap_or_default();
        let base_amount = U256::from(statement.matchResult.maxBaseAmount);
        let req = self
            .darkpool
            .processMalleableAtomicMatchSettle(
                base_amount,
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
        todo!()
    }

    fn parse_external_match(
        calldata: &[u8],
    ) -> Result<Option<ExternalMatchResult>, DarkpoolClientError> {
        todo!()
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
