//! Utilities for converting between circuit types such as statements and
//! proofs, and their analogues as expected by the smart contracts.

use alloy_primitives::Address;
use ark_bn254::g1::Config as G1Config;
use ark_ec::short_weierstrass::Affine;
use circuit_types::{
    keychain::PublicSigningKey,
    traits::BaseType,
    transfers::{ExternalTransfer, ExternalTransferDirection},
    PlonkLinkProof, PlonkProof, PolynomialCommitment, SizedWalletShare,
};
use circuits::zk_circuits::{
    valid_commitments::ValidCommitmentsStatement,
    valid_match_settle::SizedValidMatchSettleStatement, valid_reblind::ValidReblindStatement,
    valid_wallet_create::SizedValidWalletCreateStatement,
    valid_wallet_update::SizedValidWalletUpdateStatement,
};
use common::types::proof_bundles::{MatchBundle, OrderValidityProofBundle};
use constants::{Scalar, ScalarField};
use contracts_common::types::{
    ExternalTransfer as ContractExternalTransfer, LinkingProof as ContractLinkingProof,
    MatchLinkingProofs as ContractMatchLinkingProofs, MatchProofs as ContractMatchProofs,
    Proof as ContractProof, PublicSigningKey as ContractPublicSigningKey,
    ValidCommitmentsStatement as ContractValidCommitmentsStatement,
    ValidMatchSettleStatement as ContractValidMatchSettleStatement,
    ValidReblindStatement as ContractValidReblindStatement,
    ValidWalletCreateStatement as ContractValidWalletCreateStatement,
    ValidWalletUpdateStatement as ContractValidWalletUpdateStatement,
};
use ruint::aliases::{U160, U256};

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
fn to_contract_external_transfer(
    external_transfer: &ExternalTransfer,
) -> Result<ContractExternalTransfer, ConversionError> {
    let account_addr: U160 = external_transfer
        .account_addr
        .clone()
        .try_into()
        .map_err(|_| ConversionError::InvalidUint)?;
    let mint: U160 =
        external_transfer.mint.clone().try_into().map_err(|_| ConversionError::InvalidUint)?;
    let amount: U256 =
        external_transfer.amount.clone().try_into().map_err(|_| ConversionError::InvalidUint)?;

    Ok(ContractExternalTransfer {
        account_addr: Address::from(account_addr),
        mint: Address::from(mint),
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
        timestamp: statement.timestamp,
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
        balance_send_index: statement.indices.balance_send as u64,
        balance_receive_index: statement.indices.balance_receive as u64,
        order_index: statement.indices.order as u64,
    }
}

/// Convert a [`SizedValidMatchSettleStatement`] to its corresponding smart
/// contract type
pub fn to_contract_valid_match_settle_statement(
    statement: &SizedValidMatchSettleStatement,
) -> ContractValidMatchSettleStatement {
    let party0_modified_shares = wallet_shares_to_scalar_vec(&statement.party0_modified_shares);
    let party1_modified_shares = wallet_shares_to_scalar_vec(&statement.party1_modified_shares);

    ContractValidMatchSettleStatement {
        party0_modified_shares,
        party1_modified_shares,
        party0_send_balance_index: statement.party0_indices.balance_send as u64,
        party0_receive_balance_index: statement.party0_indices.balance_receive as u64,
        party0_order_index: statement.party0_indices.order as u64,
        party1_send_balance_index: statement.party1_indices.balance_send as u64,
        party1_receive_balance_index: statement.party1_indices.balance_receive as u64,
        party1_order_index: statement.party1_indices.order as u64,
    }
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

// ------------------------
// | CONVERSION UTILITIES |
// ------------------------

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
