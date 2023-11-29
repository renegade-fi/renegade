//! Shim types mirroring other proof system types that are serde-compatible
//!
//! Mirrored from https://github.com/renegade-fi/renegade-contracts/blob/main/common/src/types.rs

use alloy_primitives::Address;
use ark_bn254::{g1::Config as G1Config, Fq};
use ark_ec::short_weierstrass::Affine;
use circuit_types::{
    keychain::PublicSigningKey,
    traits::BaseType,
    transfers::{ExternalTransfer, ExternalTransferDirection},
    wallet::WalletShare,
    PlonkProof, PolynomialCommitment,
};
use circuits::zk_circuits::{
    valid_commitments::ValidCommitmentsStatement, valid_match_settle::ValidMatchSettleStatement,
    valid_reblind::ValidReblindStatement, valid_wallet_create::ValidWalletCreateStatement,
    valid_wallet_update::ValidWalletUpdateStatement,
};
use constants::{Scalar, ScalarField};
use ruint::aliases::{U160, U256};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{errors::ConversionError, serde_def_types::*};

/// The number of wire types in the circuit
pub const NUM_WIRE_TYPES: usize = 5;

/// Type alias for the affine representation of the
/// system curve's G1 group
pub type G1Affine = Affine<G1Config>;
/// Type alias for the base field of the system curve's G1 group
pub type G1BaseField = Fq;

/// A Plonk proof, using the "fast prover" strategy described in the paper.
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct ContractProof {
    /// The commitments to the wire polynomials
    #[serde_as(as = "[G1AffineDef; NUM_WIRE_TYPES]")]
    pub wire_comms: [G1Affine; NUM_WIRE_TYPES],
    /// The commitment to the grand product polynomial encoding the permutation
    /// argument (i.e., copy constraints)
    #[serde_as(as = "G1AffineDef")]
    pub z_comm: G1Affine,
    /// The commitments to the split quotient polynomials
    #[serde_as(as = "[G1AffineDef; NUM_WIRE_TYPES]")]
    pub quotient_comms: [G1Affine; NUM_WIRE_TYPES],
    /// The opening proof of evaluations at challenge point `zeta`
    #[serde_as(as = "G1AffineDef")]
    pub w_zeta: G1Affine,
    /// The opening proof of evaluations at challenge point `zeta * omega`
    #[serde_as(as = "G1AffineDef")]
    pub w_zeta_omega: G1Affine,
    /// The evaluations of the wire polynomials at the challenge point `zeta`
    #[serde_as(as = "[ScalarFieldDef; NUM_WIRE_TYPES]")]
    pub wire_evals: [ScalarField; NUM_WIRE_TYPES],
    /// The evaluations of the permutation polynomials at the challenge point
    /// `zeta`
    #[serde_as(as = "[ScalarFieldDef; NUM_WIRE_TYPES - 1]")]
    pub sigma_evals: [ScalarField; NUM_WIRE_TYPES - 1],
    /// The evaluation of the grand product polynomial at the challenge point
    /// `zeta * omega` (\bar{z})
    #[serde_as(as = "ScalarFieldDef")]
    pub z_bar: ScalarField,
}

impl TryFrom<PlonkProof> for ContractProof {
    type Error = ConversionError;

    fn try_from(value: PlonkProof) -> Result<Self, Self::Error> {
        Ok(ContractProof {
            wire_comms: try_unwrap_commitments(&value.wires_poly_comms)?,
            z_comm: value.prod_perm_poly_comm.0,
            quotient_comms: try_unwrap_commitments(&value.split_quot_poly_comms)?,
            w_zeta: value.opening_proof.0,
            w_zeta_omega: value.shifted_opening_proof.0,
            wire_evals: value
                .poly_evals
                .wires_evals
                .try_into()
                .map_err(|_| ConversionError::InvalidLength)?,
            sigma_evals: value
                .poly_evals
                .wire_sigma_evals
                .try_into()
                .map_err(|_| ConversionError::InvalidLength)?,
            z_bar: value.poly_evals.perm_next_eval,
        })
    }
}

/// Represents an external transfer of an ERC20 token
#[serde_as]
#[derive(Serialize, Deserialize, Default)]
pub struct ContractExternalTransfer {
    /// The address of the account contract to deposit from or withdraw to
    #[serde_as(as = "AddressDef")]
    pub account_addr: Address,
    /// The mint (contract address) of the token being transferred
    #[serde_as(as = "AddressDef")]
    pub mint: Address,
    /// The amount of the token transferred
    #[serde_as(as = "U256Def")]
    pub amount: U256,
    /// Whether or not the transfer is a withdrawal (otherwise a deposit)
    pub is_withdrawal: bool,
}

impl TryFrom<ExternalTransfer> for ContractExternalTransfer {
    type Error = ConversionError;

    fn try_from(value: ExternalTransfer) -> Result<Self, Self::Error> {
        let account_addr: U160 =
            value.account_addr.try_into().map_err(|_| ConversionError::InvalidUint)?;
        let mint: U160 = value.mint.try_into().map_err(|_| ConversionError::InvalidUint)?;
        let amount: U256 = value.amount.try_into().map_err(|_| ConversionError::InvalidUint)?;

        Ok(ContractExternalTransfer {
            account_addr: Address::from(account_addr),
            mint: Address::from(mint),
            amount,
            is_withdrawal: value.direction == ExternalTransferDirection::Withdrawal,
        })
    }
}

/// Represents the affine coordinates of a secp256k1 ECDSA public key.
/// Since the secp256k1 base field order is larger than that of Bn254's scalar
/// field, it takes 2 Bn254 scalar field elements to represent each coordinate.
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct ContractPublicSigningKey {
    /// The affine x-coordinate of the public key
    #[serde_as(as = "[ScalarFieldDef; 2]")]
    pub x: [ScalarField; 2],
    /// The affine y-coordinate of the public key
    #[serde_as(as = "[ScalarFieldDef; 2]")]
    pub y: [ScalarField; 2],
}

impl TryFrom<PublicSigningKey> for ContractPublicSigningKey {
    type Error = ConversionError;

    fn try_from(value: PublicSigningKey) -> Result<Self, Self::Error> {
        let x = try_unwrap_scalars(&value.x.to_scalars())?;
        let y = try_unwrap_scalars(&value.y.to_scalars())?;

        Ok(ContractPublicSigningKey { x, y })
    }
}

/// Statement for `VALID_WALLET_CREATE` circuit
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct ContractValidWalletCreateStatement {
    /// The commitment to the private secret shares of the wallet
    #[serde_as(as = "ScalarFieldDef")]
    pub private_shares_commitment: ScalarField,
    /// The blinded public secret shares of the wallet
    #[serde_as(as = "Vec<ScalarFieldDef>")]
    pub public_wallet_shares: Vec<ScalarField>,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    From<ValidWalletCreateStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>>
    for ContractValidWalletCreateStatement
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    fn from(value: ValidWalletCreateStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>) -> Self {
        let public_wallet_shares = wallet_shares_to_scalar_vec(&value.public_wallet_shares);

        ContractValidWalletCreateStatement {
            private_shares_commitment: value.private_shares_commitment.inner(),
            public_wallet_shares,
        }
    }
}

/// Statement for `VALID_WALLET_UPDATE` circuit
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct ContractValidWalletUpdateStatement {
    /// The nullifier of the old wallet's secret shares
    #[serde_as(as = "ScalarFieldDef")]
    pub old_shares_nullifier: ScalarField,
    /// A commitment to the new wallet's private secret shares
    #[serde_as(as = "ScalarFieldDef")]
    pub new_private_shares_commitment: ScalarField,
    /// The blinded public secret shares of the new wallet
    #[serde_as(as = "Vec<ScalarFieldDef>")]
    pub new_public_shares: Vec<ScalarField>,
    /// A historic merkle root for which we prove inclusion of
    /// the commitment to the old wallet's private secret shares
    #[serde_as(as = "ScalarFieldDef")]
    pub merkle_root: ScalarField,
    /// The external transfer associated with this update
    pub external_transfer: Option<ContractExternalTransfer>,
    /// The public root key of the old wallet, rotated out after this update
    pub old_pk_root: ContractPublicSigningKey,
    /// The timestamp this update was applied at
    pub timestamp: u64,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    TryFrom<ValidWalletUpdateStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>>
    for ContractValidWalletUpdateStatement
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type Error = ConversionError;

    fn try_from(
        value: ValidWalletUpdateStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    ) -> Result<Self, Self::Error> {
        let new_public_shares = wallet_shares_to_scalar_vec(&value.new_public_shares);
        let external_transfer: Option<ContractExternalTransfer> =
            if value.external_transfer == ExternalTransfer::default() {
                None
            } else {
                Some(ContractExternalTransfer::try_from(value.external_transfer)?)
            };

        let old_pk_root: ContractPublicSigningKey = value.old_pk_root.try_into()?;

        Ok(ContractValidWalletUpdateStatement {
            old_shares_nullifier: value.old_shares_nullifier.inner(),
            new_private_shares_commitment: value.new_private_shares_commitment.inner(),
            new_public_shares,
            merkle_root: value.merkle_root.inner(),
            external_transfer,
            old_pk_root,
            timestamp: value.timestamp,
        })
    }
}

/// Statement for the `VALID_REBLIND` circuit
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct ContractValidReblindStatement {
    /// The nullifier of the original wallet's secret shares
    #[serde_as(as = "ScalarFieldDef")]
    pub original_shares_nullifier: ScalarField,
    /// A commitment to the private secret shares of the reblinded wallet
    #[serde_as(as = "ScalarFieldDef")]
    pub reblinded_private_shares_commitment: ScalarField,
    /// A historic merkle root for which we prove inclusion of
    /// the commitment to the original wallet's private secret shares
    #[serde_as(as = "ScalarFieldDef")]
    pub merkle_root: ScalarField,
}

impl From<ValidReblindStatement> for ContractValidReblindStatement {
    fn from(value: ValidReblindStatement) -> Self {
        ContractValidReblindStatement {
            original_shares_nullifier: value.original_shares_nullifier.inner(),
            reblinded_private_shares_commitment: value.reblinded_private_share_commitment.inner(),
            merkle_root: value.merkle_root.inner(),
        }
    }
}

/// Statememt for the `VALID_COMMITMENTS` circuit
#[derive(Serialize, Deserialize)]
pub struct ContractValidCommitmentsStatement {
    /// The index of the balance sent by the party if a successful match occurs
    pub balance_send_index: u64,
    /// The index of the balance received by the party if a successful match
    /// occurs
    pub balance_receive_index: u64,
    /// The index of the order being matched
    pub order_index: u64,
}

impl From<ValidCommitmentsStatement> for ContractValidCommitmentsStatement {
    fn from(value: ValidCommitmentsStatement) -> Self {
        ContractValidCommitmentsStatement {
            balance_send_index: value.indices.balance_send,
            balance_receive_index: value.indices.balance_receive,
            order_index: value.indices.order,
        }
    }
}

/// Statement for the `VALID_MATCH_SETTLE` circuit
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct ContractValidMatchSettleStatement {
    /// The modified blinded public secret shares of the first party
    #[serde_as(as = "Vec<ScalarFieldDef>")]
    pub party0_modified_shares: Vec<ScalarField>,
    /// The modified blinded public secret shares of the second party
    #[serde_as(as = "Vec<ScalarFieldDef>")]
    pub party1_modified_shares: Vec<ScalarField>,
    /// The index of the balance sent by the first party in the settlement
    pub party0_send_balance_index: u64,
    /// The index of the balance received by the first party in the settlement
    pub party0_receive_balance_index: u64,
    /// The index of the first party's matched order
    pub party0_order_index: u64,
    /// The index of the balance sent by the second party in the settlement
    pub party1_send_balance_index: u64,
    /// The index of the balance received by the second party in the settlement
    pub party1_receive_balance_index: u64,
    /// The index of the second party's matched order
    pub party1_order_index: u64,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    From<ValidMatchSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>>
    for ContractValidMatchSettleStatement
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    fn from(value: ValidMatchSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>) -> Self {
        let party0_modified_shares = wallet_shares_to_scalar_vec(&value.party0_modified_shares);
        let party1_modified_shares = wallet_shares_to_scalar_vec(&value.party1_modified_shares);

        ContractValidMatchSettleStatement {
            party0_modified_shares,
            party1_modified_shares,
            party0_send_balance_index: value.party0_indices.balance_send,
            party0_receive_balance_index: value.party0_indices.balance_receive,
            party0_order_index: value.party0_indices.order,
            party1_send_balance_index: value.party1_indices.balance_send,
            party1_receive_balance_index: value.party1_indices.balance_receive,
            party1_order_index: value.party1_indices.order,
        }
    }
}

/// Represents the outputs produced by one of the parties in a match
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct MatchPayload {
    /// The public secret share of the party's wallet-level blinder
    #[serde_as(as = "ScalarFieldDef")]
    pub wallet_blinder_share: ScalarField,
    /// The statement for the party's `VALID_COMMITMENTS` proof
    pub valid_commitments_statement: ContractValidCommitmentsStatement,
    /// The statement for the party's `VALID_REBLIND` proof
    pub valid_reblind_statement: ContractValidReblindStatement,
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
fn wallet_shares_to_scalar_vec<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
>(
    shares: &WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
) -> Vec<ScalarField>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    shares.to_scalars().into_iter().map(|s| s.inner()).collect()
}
