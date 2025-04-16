//! Utilities for converting between circuit types such as statements and
//! proofs, and their analogues as expected by the smart contracts.

use std::str::FromStr;

use alloy_primitives::{Address, U256 as AlloyU256};
use ark_bn254::g1::Config as G1Config;
use ark_ec::short_weierstrass::Affine;
use circuit_types::{
    elgamal::{ElGamalCiphertext, EncryptionKey},
    fees::FeeTake,
    keychain::PublicSigningKey,
    note::NOTE_CIPHERTEXT_SIZE,
    r#match::{ExternalMatchResult, OrderSettlementIndices},
    traits::BaseType,
    transfers::{ExternalTransfer, ExternalTransferDirection},
    Amount, PlonkLinkProof, PlonkProof, PolynomialCommitment, SizedWalletShare,
};
use circuits::zk_circuits::{
    valid_commitments::ValidCommitmentsStatement,
    valid_fee_redemption::SizedValidFeeRedemptionStatement,
    valid_match_settle::SizedValidMatchSettleStatement,
    valid_match_settle_atomic::SizedValidMatchSettleAtomicStatement,
    valid_offline_fee_settlement::SizedValidOfflineFeeSettlementStatement,
    valid_reblind::ValidReblindStatement,
    valid_relayer_fee_settlement::SizedValidRelayerFeeSettlementStatement,
    valid_wallet_create::SizedValidWalletCreateStatement,
    valid_wallet_update::SizedValidWalletUpdateStatement,
};
use common::types::{
    proof_bundles::{AtomicMatchSettleBundle, MatchBundle, OrderValidityProofBundle},
    transfer_auth::TransferAuth,
};
use constants::{Scalar, ScalarField};
use num_bigint::BigUint;
use ruint::aliases::{U160, U256};
use util::hex::biguint_to_hex_string;

use crate::contract_types::{
    BabyJubJubPoint as ContractBabyJubJubPoint, ExternalMatchResult as ContractExternalMatchResult,
    ExternalTransfer as ContractExternalTransfer, FeeTake as ContractFeeTake,
    LinkingProof as ContractLinkingProof,
    MatchAtomicLinkingProofs as ContractMatchAtomicLinkingProofs,
    MatchAtomicProofs as ContractMatchAtomicProofs,
    MatchLinkingProofs as ContractMatchLinkingProofs, MatchProofs as ContractMatchProofs,
    NoteCiphertext as ContractNoteCiphertext,
    OrderSettlementIndices as ContractOrderSettlementIndices, Proof as ContractProof,
    PublicEncryptionKey as ContractPublicEncryptionKey,
    PublicSigningKey as ContractPublicSigningKey, TransferAuxData as ContractTransferAuxData,
    ValidCommitmentsStatement as ContractValidCommitmentsStatement,
    ValidFeeRedemptionStatement as ContractValidFeeRedemptionStatement,
    ValidMatchSettleAtomicStatement as ContractValidMatchSettleAtomicStatement,
    ValidMatchSettleStatement as ContractValidMatchSettleStatement,
    ValidOfflineFeeSettlementStatement as ContractValidOfflineFeeSettlementStatement,
    ValidReblindStatement as ContractValidReblindStatement,
    ValidRelayerFeeSettlementStatement as ContractValidRelayerFeeSettlementStatement,
    ValidWalletCreateStatement as ContractValidWalletCreateStatement,
    ValidWalletUpdateStatement as ContractValidWalletUpdateStatement, NUM_SCALARS_PK,
};
use crate::errors::ConversionError;

/// Type alias for the affine representation of the
/// system curve's G1 group
pub type G1Affine = Affine<G1Config>;

/// Convert a [`PlonkProof`] to its corresponding smart contract type
pub fn to_contract_proof(proof: &PlonkProof) -> Result<ContractProof, ConversionError> {
    Ok(ContractProof {
        wire_comms: try_unwrap_commitments(&proof.wires_poly_comms)?,
        z_comm: proof.prod_perm_poly_comm.0,
        quotient_comms: try_unwrap_commitments(&proof.split_quot_poly_comms)?,
        w_zeta: proof.opening_proof.0,
        w_zeta_omega: proof.shifted_opening_proof.0,
        wire_evals: proof
            .poly_evals
            .wires_evals
            .clone()
            .try_into()
            .map_err(|_| ConversionError::InvalidLength)?,
        sigma_evals: proof
            .poly_evals
            .wire_sigma_evals
            .clone()
            .try_into()
            .map_err(|_| ConversionError::InvalidLength)?,
        z_bar: proof.poly_evals.perm_next_eval,
    })
}

/// Convert a [`LinkingProof`] to its corresponding smart contract type
pub fn to_contract_link_proof(
    proof: &PlonkLinkProof,
) -> Result<ContractLinkingProof, ConversionError> {
    Ok(ContractLinkingProof {
        linking_poly_opening: proof.opening_proof.proof,
        linking_quotient_poly_comm: proof.quotient_commitment.0,
    })
}

/// Convert an [`ExternalTransfer`] to its corresponding smart contract type
pub fn to_contract_external_transfer(
    external_transfer: &ExternalTransfer,
) -> Result<ContractExternalTransfer, ConversionError> {
    let account_addr = biguint_to_address(&external_transfer.account_addr)?;
    let mint = biguint_to_address(&external_transfer.mint)?;
    let amount = amount_to_u256(external_transfer.amount)?;

    Ok(ContractExternalTransfer {
        account_addr,
        mint,
        amount,
        is_withdrawal: external_transfer.direction == ExternalTransferDirection::Withdrawal,
    })
}

/// Convert a [`PublicSigningKey`] to its corresponding smart contract type
pub fn to_contract_public_signing_key(
    public_signing_key: &PublicSigningKey,
) -> Result<ContractPublicSigningKey, ConversionError> {
    let x = try_unwrap_scalars(&public_signing_key.x.to_scalars())?;
    let y = try_unwrap_scalars(&public_signing_key.y.to_scalars())?;

    Ok(ContractPublicSigningKey { x, y })
}

/// Convert a [`SizedValidWalletCreateStatement`] to its corresponding smart
/// contract type
pub fn to_contract_valid_wallet_create_statement(
    statement: &SizedValidWalletCreateStatement,
) -> ContractValidWalletCreateStatement {
    let public_wallet_shares = wallet_shares_to_scalar_vec(&statement.public_wallet_shares);

    ContractValidWalletCreateStatement {
        private_shares_commitment: statement.private_shares_commitment.inner(),
        public_wallet_shares,
    }
}

/// Convert a [`SizedValidWalletUpdateStatement`] to its corresponding smart
/// contract type
pub fn to_contract_valid_wallet_update_statement(
    statement: &SizedValidWalletUpdateStatement,
) -> Result<ContractValidWalletUpdateStatement, ConversionError> {
    let new_public_shares = wallet_shares_to_scalar_vec(&statement.new_public_shares);
    let external_transfer: Option<ContractExternalTransfer> =
        if statement.external_transfer.is_default() {
            None
        } else {
            Some(to_contract_external_transfer(&statement.external_transfer)?)
        };

    let old_pk_root = to_contract_public_signing_key(&statement.old_pk_root)?;

    Ok(ContractValidWalletUpdateStatement {
        old_shares_nullifier: statement.old_shares_nullifier.inner(),
        new_private_shares_commitment: statement.new_private_shares_commitment.inner(),
        new_public_shares,
        merkle_root: statement.merkle_root.inner(),
        external_transfer,
        old_pk_root,
    })
}

/// Convert a [`TransferAuth`] to its corresponding smart contract type
pub fn to_contract_transfer_aux_data(
    data: TransferAuth,
) -> Result<ContractTransferAuxData, ConversionError> {
    Ok(match data {
        TransferAuth::Deposit(deposit) => ContractTransferAuxData {
            permit_nonce: Some(
                AlloyU256::from_str(&biguint_to_hex_string(&deposit.permit_nonce))
                    .map_err(|_| ConversionError::InvalidUint)?,
            ),
            permit_deadline: Some(
                AlloyU256::from_str(&biguint_to_hex_string(&deposit.permit_deadline))
                    .map_err(|_| ConversionError::InvalidUint)?,
            ),
            permit_signature: Some(deposit.permit_signature.clone()),
            transfer_signature: None,
        },
        TransferAuth::Withdrawal(withdrawal) => ContractTransferAuxData {
            permit_nonce: None,
            permit_deadline: None,
            permit_signature: None,
            transfer_signature: Some(withdrawal.external_transfer_signature.clone()),
        },
    })
}

/// Convert a [`ValidReblindStatement`] to its corresponding smart contract type
pub fn to_contract_valid_reblind_statement(
    statement: &ValidReblindStatement,
) -> ContractValidReblindStatement {
    ContractValidReblindStatement {
        original_shares_nullifier: statement.original_shares_nullifier.inner(),
        reblinded_private_shares_commitment: statement.reblinded_private_share_commitment.inner(),
        merkle_root: statement.merkle_root.inner(),
    }
}

/// Convert a [`ValidCommitmentsStatement`] to its corresponding smart contract
/// type
pub fn to_contract_valid_commitments_statement(
    statement: ValidCommitmentsStatement,
) -> ContractValidCommitmentsStatement {
    ContractValidCommitmentsStatement {
        indices: ContractOrderSettlementIndices {
            balance_send: statement.indices.balance_send as u64,
            balance_receive: statement.indices.balance_receive as u64,
            order: statement.indices.order as u64,
        },
    }
}

/// Convert `OrderSettlementIndices` to its corresponding smart contract type
pub fn to_contract_order_settlement_indices(
    indices: &OrderSettlementIndices,
) -> ContractOrderSettlementIndices {
    ContractOrderSettlementIndices {
        balance_send: indices.balance_send as u64,
        balance_receive: indices.balance_receive as u64,
        order: indices.order as u64,
    }
}

/// Convert a [`SizedValidMatchSettleStatement`] to its corresponding smart
/// contract type
pub fn to_contract_valid_match_settle_statement(
    statement: &SizedValidMatchSettleStatement,
) -> ContractValidMatchSettleStatement {
    let party0_modified_shares = wallet_shares_to_scalar_vec(&statement.party0_modified_shares);
    let party1_modified_shares = wallet_shares_to_scalar_vec(&statement.party1_modified_shares);
    let party0_indices = to_contract_order_settlement_indices(&statement.party0_indices);
    let party1_indices = to_contract_order_settlement_indices(&statement.party1_indices);

    ContractValidMatchSettleStatement {
        party0_modified_shares,
        party1_modified_shares,
        party0_indices,
        party1_indices,
        protocol_fee: statement.protocol_fee.repr.inner(),
    }
}

/// Convert a [`ExternalMatchResult`] to its corresponding smart contract type
pub fn to_contract_external_match_result(
    match_result: &ExternalMatchResult,
) -> Result<ContractExternalMatchResult, ConversionError> {
    let quote_mint = biguint_to_address(&match_result.quote_mint)?;
    let base_mint = biguint_to_address(&match_result.base_mint)?;
    let quote_amount = amount_to_u256(match_result.quote_amount)?;
    let base_amount = amount_to_u256(match_result.base_amount)?;

    Ok(ContractExternalMatchResult {
        quote_mint,
        base_mint,
        quote_amount,
        base_amount,
        direction: match_result.direction,
    })
}

/// Convert a [`FeeTake`] to its corresponding smart contract type
pub fn to_contract_fee_take(fee_take: &FeeTake) -> Result<ContractFeeTake, ConversionError> {
    Ok(ContractFeeTake {
        relayer_fee: amount_to_u256(fee_take.relayer_fee)?,
        protocol_fee: amount_to_u256(fee_take.protocol_fee)?,
    })
}

/// Convert a [`SizedValidMatchSettleAtomicStatement`] to its corresponding
/// smart contract type
pub fn to_contract_valid_match_settle_atomic_statement(
    statement: &SizedValidMatchSettleAtomicStatement,
) -> Result<ContractValidMatchSettleAtomicStatement, ConversionError> {
    let internal_party_modified_shares =
        wallet_shares_to_scalar_vec(&statement.internal_party_modified_shares);
    let internal_party_indices =
        to_contract_order_settlement_indices(&statement.internal_party_indices);

    Ok(ContractValidMatchSettleAtomicStatement {
        match_result: to_contract_external_match_result(&statement.match_result)?,
        external_party_fees: to_contract_fee_take(&statement.external_party_fees)?,
        internal_party_modified_shares,
        internal_party_indices,
        protocol_fee: statement.protocol_fee.repr.inner(),
        relayer_fee_address: biguint_to_address(&statement.relayer_fee_address)?,
    })
}

/// Build a [`MatchProofs`] contract type from a set of proof bundles
pub fn build_match_proofs(
    party0_validity_proofs: &OrderValidityProofBundle,
    party1_validity_proofs: &OrderValidityProofBundle,
    match_settle_proof: &PlonkProof,
) -> Result<ContractMatchProofs, ConversionError> {
    Ok(ContractMatchProofs {
        valid_commitments_0: to_contract_proof(&party0_validity_proofs.commitment_proof.proof)?,
        valid_reblind_0: to_contract_proof(&party0_validity_proofs.reblind_proof.proof)?,
        valid_commitments_1: to_contract_proof(&party1_validity_proofs.commitment_proof.proof)?,
        valid_reblind_1: to_contract_proof(&party1_validity_proofs.reblind_proof.proof)?,
        valid_match_settle: to_contract_proof(match_settle_proof)?,
    })
}

/// Build a [`MatchLinkingProofs`] contract type from a set of match linking
/// bundles
pub fn build_match_linking_proofs(
    party0_validity_proofs: &OrderValidityProofBundle,
    party1_validity_proofs: &OrderValidityProofBundle,
    match_bundle: &MatchBundle,
) -> Result<ContractMatchLinkingProofs, ConversionError> {
    Ok(ContractMatchLinkingProofs {
        valid_reblind_commitments_0: to_contract_link_proof(&party0_validity_proofs.linking_proof)?,
        valid_reblind_commitments_1: to_contract_link_proof(&party1_validity_proofs.linking_proof)?,
        valid_commitments_match_settle_0: to_contract_link_proof(&match_bundle.commitments_link0)?,
        valid_commitments_match_settle_1: to_contract_link_proof(&match_bundle.commitments_link1)?,
    })
}

/// Build a [`MatchAtomicProofs`] contract type from a set of atomic match
/// proofs
pub fn build_atomic_match_proofs(
    internal_party_validity_proofs: &OrderValidityProofBundle,
    atomic_match_proof: &PlonkProof,
) -> Result<ContractMatchAtomicProofs, ConversionError> {
    Ok(ContractMatchAtomicProofs {
        valid_commitments: to_contract_proof(
            &internal_party_validity_proofs.commitment_proof.proof,
        )?,
        valid_reblind: to_contract_proof(&internal_party_validity_proofs.reblind_proof.proof)?,
        valid_match_settle_atomic: to_contract_proof(atomic_match_proof)?,
    })
}

/// Build a [`MatchAtomicLinkingProofs`] contract type from a set of atomic
/// match linking proofs
pub fn build_atomic_match_linking_proofs(
    internal_party_validity_proofs: &OrderValidityProofBundle,
    match_bundle: &AtomicMatchSettleBundle,
) -> Result<ContractMatchAtomicLinkingProofs, ConversionError> {
    Ok(ContractMatchAtomicLinkingProofs {
        valid_reblind_commitments: to_contract_link_proof(
            &internal_party_validity_proofs.linking_proof,
        )?,
        valid_commitments_match_settle_atomic: to_contract_link_proof(
            &match_bundle.commitments_link,
        )?,
    })
}

/// Converts a [`SizedValidRelayerFeeSettlementStatement`] (from prover-side
/// code) to a [`ContractValidRelayerFeeSettlementStatement`]
pub fn to_contract_valid_relayer_fee_settlement_statement(
    statement: &SizedValidRelayerFeeSettlementStatement,
) -> Result<ContractValidRelayerFeeSettlementStatement, ConversionError> {
    Ok(ContractValidRelayerFeeSettlementStatement {
        sender_root: statement.sender_root.inner(),
        recipient_root: statement.recipient_root.inner(),
        sender_nullifier: statement.sender_nullifier.inner(),
        recipient_nullifier: statement.recipient_nullifier.inner(),
        sender_wallet_commitment: statement.sender_wallet_commitment.inner(),
        recipient_wallet_commitment: statement.recipient_wallet_commitment.inner(),
        sender_updated_public_shares: statement
            .sender_updated_public_shares
            .to_scalars()
            .iter()
            .map(|s| s.inner())
            .collect(),
        recipient_updated_public_shares: statement
            .recipient_updated_public_shares
            .to_scalars()
            .iter()
            .map(|s| s.inner())
            .collect(),
        recipient_pk_root: to_contract_public_signing_key(&statement.recipient_pk_root)?,
    })
}

/// Converts a [`ElGamalCiphertext`] (from prover-side code) to a
/// [`ContractNoteCiphertext`]
pub fn to_contract_note_ciphertext(
    note_ciphertext: &ElGamalCiphertext<NOTE_CIPHERTEXT_SIZE>,
) -> ContractNoteCiphertext {
    ContractNoteCiphertext(
        ContractBabyJubJubPoint {
            x: note_ciphertext.ephemeral_key.x.inner(),
            y: note_ciphertext.ephemeral_key.y.inner(),
        },
        note_ciphertext.ciphertext[0].inner(),
        note_ciphertext.ciphertext[1].inner(),
        note_ciphertext.ciphertext[2].inner(),
    )
}

/// Converts an [`EncryptionKey`] (from prover-side code) to a
/// [`ContractPublicEncryptionKey`]
pub fn to_contract_public_encryption_key(
    public_encryption_key: &EncryptionKey,
) -> ContractPublicEncryptionKey {
    ContractPublicEncryptionKey {
        x: public_encryption_key.x.inner(),
        y: public_encryption_key.y.inner(),
    }
}

/// Converts a [`SizedValidOfflineFeeSettlementStatement`] (from prover-side
/// code) to a [`ContractValidOfflineFeeSettlementStatement`]
pub fn to_contract_valid_offline_fee_settlement_statement(
    statement: &SizedValidOfflineFeeSettlementStatement,
) -> ContractValidOfflineFeeSettlementStatement {
    ContractValidOfflineFeeSettlementStatement {
        merkle_root: statement.merkle_root.inner(),
        nullifier: statement.nullifier.inner(),
        updated_wallet_commitment: statement.updated_wallet_commitment.inner(),
        updated_wallet_public_shares: statement
            .updated_wallet_public_shares
            .to_scalars()
            .iter()
            .map(|s| s.inner())
            .collect(),
        note_ciphertext: to_contract_note_ciphertext(&statement.note_ciphertext),
        note_commitment: statement.note_commitment.inner(),
        protocol_key: to_contract_public_encryption_key(&statement.protocol_key),
        is_protocol_fee: statement.is_protocol_fee,
    }
}

/// Converts a [`SizedValidFeeRedemptionStatement`] (from prover-side code) to a
/// [`ContractValidFeeRedemptionStatement`]
pub fn to_contract_valid_fee_redemption_statement(
    statement: &SizedValidFeeRedemptionStatement,
) -> Result<ContractValidFeeRedemptionStatement, ConversionError> {
    Ok(ContractValidFeeRedemptionStatement {
        wallet_root: statement.wallet_root.inner(),
        note_root: statement.note_root.inner(),
        nullifier: statement.wallet_nullifier.inner(),
        note_nullifier: statement.note_nullifier.inner(),
        new_wallet_commitment: statement.new_wallet_commitment.inner(),
        new_wallet_public_shares: statement
            .new_wallet_public_shares
            .to_scalars()
            .iter()
            .map(|s| s.inner())
            .collect(),
        old_pk_root: to_contract_public_signing_key(&statement.recipient_root_key)?,
    })
}

/// Converts a [`PublicSigningKey`] to a fixed-length array of [`AlloyU256`]
/// elements
pub fn pk_to_u256s(pk: &PublicSigningKey) -> Result<[AlloyU256; NUM_SCALARS_PK], ConversionError> {
    pk.to_scalars()
        .iter()
        .map(|s| scalar_to_u256(*s))
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| ConversionError::InvalidLength)
}

// ------------------------
// | CONVERSION UTILITIES |
// ------------------------

/// Convert a `BigUint` to an `Address`
pub fn biguint_to_address(biguint: &BigUint) -> Result<Address, ConversionError> {
    let u160: U160 = biguint.try_into().map_err(|_| ConversionError::InvalidUint)?;
    Ok(Address::from(u160))
}

/// Convert an `Address` to a `BigUint`
pub fn address_to_biguint(address: &Address) -> Result<BigUint, ConversionError> {
    let bytes = address.0.to_vec();
    Ok(BigUint::from_bytes_be(&bytes))
}

/// Convert an `Amount` to a `U256`
pub fn amount_to_u256(amount: Amount) -> Result<U256, ConversionError> {
    amount.try_into().map_err(|_| ConversionError::InvalidUint)
}

/// Convert a `U256` to an `Amount`
pub fn u256_to_amount(u256: U256) -> Result<Amount, ConversionError> {
    let bytes: [u8; 16] =
        u256.to_be_bytes_vec().try_into().map_err(|_| ConversionError::InvalidUint)?;
    let amount = Amount::from_be_bytes(bytes);
    Ok(amount)
}

/// Converts a `Scalar` to a `U256`
pub fn scalar_to_u256(scalar: Scalar) -> U256 {
    U256::from_be_slice(&scalar.to_bytes_be())
}

/// Try to extract a fixed-length array of G1Affine points
/// from a slice of proof system commitments
pub fn try_unwrap_commitments<const N: usize>(
    comms: &[PolynomialCommitment],
) -> Result<[G1Affine; N], ConversionError> {
    comms
        .iter()
        .map(|c| c.0)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| ConversionError::InvalidLength)
}

/// Try to extract a fixed-length array of `ScalarField` elements
/// from a slice of `Scalar`s
fn try_unwrap_scalars<const N: usize>(
    scalars: &[Scalar],
) -> Result<[ScalarField; N], ConversionError> {
    scalars
        .iter()
        .map(|s| s.inner())
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| ConversionError::InvalidLength)
}

/// Convert a set of wallet secret shares into a vector of `ScalarField`
/// elements
fn wallet_shares_to_scalar_vec(shares: &SizedWalletShare) -> Vec<ScalarField> {
    shares.to_scalars().into_iter().map(|s| s.inner()).collect()
}
