//! Type conversion utilities for the Base darkpool implementation

use alloy::primitives::Bytes;
use alloy::primitives::U256;
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use circuit_types::keychain::PublicSigningKey;
use circuit_types::r#match::OrderSettlementIndices as CircuitOrderSettlementIndices;
use circuit_types::traits::BaseType;
use circuit_types::transfers::ExternalTransfer as CircuitExternalTransfer;
use circuit_types::transfers::ExternalTransferDirection;
use circuit_types::PlonkLinkProof as CircuitPlonkLinkProof;
use circuit_types::PlonkProof as CircuitPlonkProof;
use circuit_types::PolynomialCommitment;
use circuits::zk_circuits::valid_commitments::ValidCommitmentsStatement as CircuitValidCommitmentsStatement;
use circuits::zk_circuits::valid_match_settle::{
    SizedValidMatchSettleStatement, SizedValidMatchSettleWithCommitmentsStatement,
};
use circuits::zk_circuits::valid_reblind::ValidReblindStatement as CircuitValidReblindStatement;
use circuits::zk_circuits::valid_wallet_create::SizedValidWalletCreateStatement;
use circuits::zk_circuits::valid_wallet_update::SizedValidWalletUpdateStatement;
use common::types::proof_bundles::OrderValidityProofBundle;
use common::types::transfer_auth::TransferAuth as CircuitTransferAuth;
use constants::Scalar;

use renegade_solidity_abi::IDarkpool::*;
use renegade_solidity_abi::BN254::G1Point;

use crate::conversion::biguint_to_address;
use crate::conversion::biguint_to_u256;
use crate::conversion::scalar_to_u256;

/// A helper method to convert a circuit type into a contract type
pub(crate) fn to_contract_type<T, C>(t: T) -> C
where
    C: From<ConversionWrapper<T>>,
{
    C::from(ConversionWrapper(t))
}

/// A wrapper type that allows us to define conversions between circuit and
/// contract types outside of the circuit crate
struct ConversionWrapper<T>(T);
impl<T> From<T> for ConversionWrapper<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl From<ConversionWrapper<SizedValidWalletCreateStatement>> for ValidWalletCreateStatement {
    fn from(wrapper: ConversionWrapper<SizedValidWalletCreateStatement>) -> Self {
        let statement = wrapper.0;
        Self {
            walletShareCommitment: scalar_to_u256(statement.wallet_share_commitment),
            publicShares: statement
                .public_wallet_shares
                .to_scalars()
                .into_iter()
                .map(scalar_to_u256)
                .collect(),
        }
    }
}

/// Convert a relayer [`SizedValidWalletUpdateStatement`] to a contract
/// [`ValidWalletUpdateStatement`]
impl From<ConversionWrapper<SizedValidWalletUpdateStatement>> for ValidWalletUpdateStatement {
    fn from(wrapper: ConversionWrapper<SizedValidWalletUpdateStatement>) -> Self {
        let statement = wrapper.0;
        Self {
            previousNullifier: scalar_to_u256(statement.old_shares_nullifier),
            newWalletCommitment: scalar_to_u256(statement.new_wallet_commitment),
            newPublicShares: statement
                .new_public_shares
                .to_scalars()
                .into_iter()
                .map(scalar_to_u256)
                .collect(),
            merkleRoot: scalar_to_u256(statement.merkle_root),
            externalTransfer: to_contract_type(statement.external_transfer),
            oldPkRoot: to_contract_type(statement.old_pk_root),
        }
    }
}

impl From<ConversionWrapper<CircuitValidReblindStatement>> for ValidReblindStatement {
    fn from(wrapper: ConversionWrapper<CircuitValidReblindStatement>) -> Self {
        let statement = wrapper.0;
        Self {
            originalSharesNullifier: scalar_to_u256(statement.original_shares_nullifier),
            newPrivateShareCommitment: scalar_to_u256(statement.reblinded_private_share_commitment),
            merkleRoot: scalar_to_u256(statement.merkle_root),
        }
    }
}

impl From<ConversionWrapper<CircuitValidCommitmentsStatement>> for ValidCommitmentsStatement {
    fn from(wrapper: ConversionWrapper<CircuitValidCommitmentsStatement>) -> Self {
        let statement = wrapper.0;
        Self { indices: to_contract_type(statement.indices) }
    }
}

impl From<ConversionWrapper<OrderValidityProofBundle>> for PartyMatchPayload {
    fn from(wrapper: ConversionWrapper<OrderValidityProofBundle>) -> Self {
        let proof_bundle = wrapper.0;
        let commitments_statement =
            to_contract_type(proof_bundle.commitment_proof.statement.clone());
        let reblind_statement = to_contract_type(proof_bundle.reblind_proof.statement.clone());
        PartyMatchPayload {
            validCommitmentsStatement: commitments_statement,
            validReblindStatement: reblind_statement,
        }
    }
}

impl From<ConversionWrapper<SizedValidMatchSettleStatement>> for ValidMatchSettleStatement {
    fn from(wrapper: ConversionWrapper<SizedValidMatchSettleStatement>) -> Self {
        let statement = wrapper.0;
        Self {
            firstPartyPublicShares: statement
                .party0_modified_shares
                .to_scalars()
                .into_iter()
                .map(scalar_to_u256)
                .collect(),
            secondPartyPublicShares: statement
                .party1_modified_shares
                .to_scalars()
                .into_iter()
                .map(scalar_to_u256)
                .collect(),
            firstPartySettlementIndices: to_contract_type(statement.party0_indices),
            secondPartySettlementIndices: to_contract_type(statement.party1_indices),
            protocolFeeRate: scalar_to_u256(statement.protocol_fee.repr),
        }
    }
}

impl From<ConversionWrapper<SizedValidMatchSettleWithCommitmentsStatement>>
    for ValidMatchSettleWithCommitmentsStatement
{
    fn from(wrapper: ConversionWrapper<SizedValidMatchSettleWithCommitmentsStatement>) -> Self {
        let statement = wrapper.0;
        Self {
            privateShareCommitment0: scalar_to_u256(statement.private_share_commitment0),
            privateShareCommitment1: scalar_to_u256(statement.private_share_commitment1),
            newShareCommitment0: scalar_to_u256(statement.new_share_commitment0),
            newShareCommitment1: scalar_to_u256(statement.new_share_commitment1),
            firstPartyPublicShares: statement
                .party0_modified_shares
                .to_scalars()
                .into_iter()
                .map(scalar_to_u256)
                .collect(),
            secondPartyPublicShares: statement
                .party1_modified_shares
                .to_scalars()
                .into_iter()
                .map(scalar_to_u256)
                .collect(),
            firstPartySettlementIndices: to_contract_type(statement.party0_indices),
            secondPartySettlementIndices: to_contract_type(statement.party1_indices),
            protocolFeeRate: scalar_to_u256(statement.protocol_fee.repr),
        }
    }
}

// ---------------------
// | Application Types |
// ---------------------

/// Convert a relayer [`ExternalTransfer`] to a contract [`ExternalTransfer`]
impl From<ConversionWrapper<CircuitExternalTransfer>> for ExternalTransfer {
    fn from(wrapper: ConversionWrapper<CircuitExternalTransfer>) -> Self {
        let transfer = wrapper.0;
        let transfer_type = match transfer.direction {
            ExternalTransferDirection::Deposit => 0,
            ExternalTransferDirection::Withdrawal => 1,
        };

        ExternalTransfer {
            account: biguint_to_address(&transfer.account_addr).expect("invalid account"),
            mint: biguint_to_address(&transfer.mint).expect("invalid mint"),
            amount: U256::from(transfer.amount),
            transferType: transfer_type,
        }
    }
}

impl From<ConversionWrapper<CircuitTransferAuth>> for TransferAuthorization {
    fn from(wrapper: ConversionWrapper<CircuitTransferAuth>) -> Self {
        let auth = wrapper.0;
        match auth {
            CircuitTransferAuth::Deposit(deposit_auth) => {
                let permit_sig = Bytes::from(deposit_auth.permit_signature);
                let permit_deadline =
                    biguint_to_u256(&deposit_auth.permit_deadline).expect("invalid deadline");
                let permit_nonce =
                    biguint_to_u256(&deposit_auth.permit_nonce).expect("invalid nonce");

                TransferAuthorization {
                    permit2Nonce: permit_nonce,
                    permit2Deadline: permit_deadline,
                    permit2Signature: permit_sig,
                    externalTransferSignature: Bytes::default(),
                }
            },
            CircuitTransferAuth::Withdrawal(withdrawal_auth) => TransferAuthorization {
                permit2Nonce: U256::ZERO,
                permit2Deadline: U256::ZERO,
                permit2Signature: Bytes::default(),
                externalTransferSignature: Bytes::from(withdrawal_auth.external_transfer_signature),
            },
        }
    }
}

/// Convert a relayer [`PublicSigningKey`] to a contract [`PublicRootKey`]
impl From<ConversionWrapper<PublicSigningKey>> for PublicRootKey {
    fn from(wrapper: ConversionWrapper<PublicSigningKey>) -> Self {
        let key = wrapper.0;
        let x_words = &key.x.scalar_words;
        let y_words = &key.y.scalar_words;
        let x = [scalar_to_u256(x_words[0]), scalar_to_u256(x_words[1])];
        let y = [scalar_to_u256(y_words[0]), scalar_to_u256(y_words[1])];

        PublicRootKey { x, y }
    }
}

/// Convert a relayer [`OrderSettlementIndices`] to a contract
/// [`OrderSettlementIndices`]
impl From<ConversionWrapper<CircuitOrderSettlementIndices>> for OrderSettlementIndices {
    fn from(wrapper: ConversionWrapper<CircuitOrderSettlementIndices>) -> Self {
        let indices = wrapper.0;
        Self {
            balanceSend: U256::from(indices.balance_send),
            balanceReceive: U256::from(indices.balance_receive),
            order: U256::from(indices.order),
        }
    }
}

// ----------------------
// | Proof System Types |
// ----------------------

/// Convert from a relayer's `PlonkProof` to a contract's `Proof`
impl From<ConversionWrapper<CircuitPlonkProof>> for PlonkProof {
    fn from(wrapper: ConversionWrapper<CircuitPlonkProof>) -> Self {
        let proof = wrapper.0;
        let evals = proof.poly_evals;
        Self {
            wire_comms: size_vec(
                proof.wires_poly_comms.into_iter().map(convert_jf_commitment).collect(),
            ),
            z_comm: convert_jf_commitment(proof.prod_perm_poly_comm),
            quotient_comms: size_vec(
                proof.split_quot_poly_comms.into_iter().map(convert_jf_commitment).collect(),
            ),
            w_zeta: convert_jf_commitment(proof.opening_proof),
            w_zeta_omega: convert_jf_commitment(proof.shifted_opening_proof),
            wire_evals: size_vec(evals.wires_evals.into_iter().map(fr_to_u256).collect()),
            sigma_evals: size_vec(evals.wire_sigma_evals.into_iter().map(fr_to_u256).collect()),
            z_bar: fr_to_u256(evals.perm_next_eval),
        }
    }
}

impl From<ConversionWrapper<CircuitPlonkLinkProof>> for LinkingProof {
    fn from(wrapper: ConversionWrapper<CircuitPlonkLinkProof>) -> Self {
        let proof = wrapper.0;
        Self {
            linking_quotient_poly_comm: convert_jf_commitment(proof.quotient_commitment),
            linking_poly_opening: convert_g1_point(proof.opening_proof.proof),
        }
    }
}

// -----------
// | Helpers |
// -----------

/// Size a vector of values to be a known fixed size
pub fn size_vec<const N: usize, T>(vec: Vec<T>) -> [T; N] {
    let size = vec.len();
    if size != N {
        panic!("vector is not the correct size: expected {N}, got {size}");
    }
    vec.try_into().map_err(|_| ()).unwrap()
}

/// Convert a `Fr` to a `U256`
///
/// This is the same field as `Scalar`, but must first be wrapped
fn fr_to_u256(fr: ark_bn254::Fr) -> U256 {
    scalar_to_u256(Scalar::new(fr))
}

/// Convert a point in the BN254 base field to a Uint256
fn base_field_to_u256(fq: ark_bn254::Fq) -> U256 {
    let bytes = fq.into_bigint().to_bytes_be();
    bytes_to_u256(&bytes)
}

/// Convert a set of big endian bytes to a Uint256
///
/// Handles padding as necessary
fn bytes_to_u256(bytes: &[u8]) -> U256 {
    let mut buf = [0u8; 32];
    buf[..bytes.len()].copy_from_slice(bytes);
    U256::from_be_bytes(buf)
}

/// Pad big endian bytes to a fixed size
fn pad_bytes<const N: usize>(bytes: &[u8]) -> [u8; N] {
    assert!(bytes.len() <= N, "bytes are too long for padding");

    let mut padded = [0u8; N];
    padded[N - bytes.len()..].copy_from_slice(bytes);
    padded
}

// --- Curve Points --- //

/// Convert a point on the BN254 curve to a `G1Point` in the contract's format
fn convert_g1_point(point: ark_bn254::G1Affine) -> G1Point {
    let x = point.x().expect("x is zero");
    let y = point.y().expect("y is zero");

    G1Point { x: base_field_to_u256(*x), y: base_field_to_u256(*y) }
}

/// Convert a `JfCommitment` to a `G1Point`
fn convert_jf_commitment(commitment: PolynomialCommitment) -> G1Point {
    convert_g1_point(commitment.0)
}
