//! Type conversion utilities for the Base darkpool implementation

use alloy::primitives::Bytes;
use alloy::primitives::U256;
use ark_ff::{BigInteger, PrimeField};
use circuit_types::PlonkLinkProof as CircuitPlonkLinkProof;
use circuit_types::PlonkProof as CircuitPlonkProof;
use circuit_types::PolynomialCommitment;
use circuit_types::elgamal::BabyJubJubPoint as CircuitJubJubPoint;
use circuit_types::elgamal::ElGamalCiphertext as CircuitElGamalCiphertext;
use circuit_types::fees::{FeeTake as CircuitFeeTake, FeeTakeRate as CircuitFeeTakeRate};
use circuit_types::fixed_point::FixedPoint as CircuitFixedPoint;
use circuit_types::keychain::PublicSigningKey;
use circuit_types::r#match::BoundedMatchResult as CircuitBoundedMatchResult;
use circuit_types::r#match::ExternalMatchResult as CircuitExternalMatchResult;
use circuit_types::r#match::OrderSettlementIndices as CircuitOrderSettlementIndices;
use circuit_types::note::NOTE_CIPHERTEXT_SIZE;
use circuit_types::traits::BaseType;
use circuit_types::transfers::ExternalTransfer as CircuitExternalTransfer;
use circuit_types::transfers::ExternalTransferDirection;
use circuits::zk_circuits::valid_commitments::ValidCommitmentsStatement as CircuitValidCommitmentsStatement;
use circuits::zk_circuits::valid_fee_redemption::SizedValidFeeRedemptionStatement;
use circuits::zk_circuits::valid_malleable_match_settle_atomic::SizedValidMalleableMatchSettleAtomicStatement;
use circuits::zk_circuits::valid_match_settle::{
    SizedValidMatchSettleStatement, SizedValidMatchSettleWithCommitmentsStatement,
};
use circuits::zk_circuits::valid_match_settle_atomic::SizedValidMatchSettleAtomicStatement;
use circuits::zk_circuits::valid_offline_fee_settlement::SizedValidOfflineFeeSettlementStatement;
use circuits::zk_circuits::valid_reblind::ValidReblindStatement as CircuitValidReblindStatement;
use circuits::zk_circuits::valid_wallet_create::SizedValidWalletCreateStatement;
use circuits::zk_circuits::valid_wallet_update::SizedValidWalletUpdateStatement;
use common::types::proof_bundles::OrderValidityProofBundle;
use common::types::transfer_auth::TransferAuth as CircuitTransferAuth;
use constants::Scalar;

use renegade_solidity_abi::BN254::G1Point;
use renegade_solidity_abi::IDarkpool::*;

use crate::conversion::address_to_biguint;
use crate::conversion::biguint_to_address;
use crate::conversion::biguint_to_u256;
use crate::conversion::scalar_to_u256;
use crate::conversion::u256_to_amount;
use crate::conversion::u256_to_scalar;
use crate::errors::ConversionError;
use crate::errors::DarkpoolClientError;

// ----------
// | Traits |
// ----------

/// Convert a relayer type into a contract type
///
/// We define this trait here to allow us to implement conversions between two
/// types that are defined in different crates
pub trait ToContractType {
    /// The type that this trait converts to
    type ContractType;
    /// Convert a circuit type into a contract type
    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError>;
}

/// Convert a contract type into a relayer type
///
/// We define this trait here to allow us to implement conversions between two
/// types that are defined in different crates
pub trait ToCircuitType {
    /// The type that this trait converts to
    type CircuitType;
    /// Convert a contract type into a circuit type
    fn to_circuit_type(&self) -> Result<Self::CircuitType, DarkpoolClientError>;
}

// -------------------
// | Statement Types |
// -------------------

impl ToContractType for SizedValidWalletCreateStatement {
    type ContractType = ValidWalletCreateStatement;

    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError> {
        Ok(Self::ContractType {
            walletShareCommitment: scalar_to_u256(self.wallet_share_commitment),
            publicShares: self
                .public_wallet_shares
                .to_scalars()
                .into_iter()
                .map(scalar_to_u256)
                .collect(),
        })
    }
}

impl ToContractType for SizedValidWalletUpdateStatement {
    type ContractType = ValidWalletUpdateStatement;

    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError> {
        Ok(Self::ContractType {
            previousNullifier: scalar_to_u256(self.old_shares_nullifier),
            newWalletCommitment: scalar_to_u256(self.new_wallet_commitment),
            newPublicShares: self
                .new_public_shares
                .to_scalars()
                .into_iter()
                .map(scalar_to_u256)
                .collect(),
            merkleRoot: scalar_to_u256(self.merkle_root),
            externalTransfer: self.external_transfer.to_contract_type()?,
            oldPkRoot: self.old_pk_root.to_contract_type()?,
        })
    }
}

impl ToContractType for CircuitValidReblindStatement {
    type ContractType = ValidReblindStatement;

    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError> {
        Ok(Self::ContractType {
            originalSharesNullifier: scalar_to_u256(self.original_shares_nullifier),
            newPrivateShareCommitment: scalar_to_u256(self.reblinded_private_share_commitment),
            merkleRoot: scalar_to_u256(self.merkle_root),
        })
    }
}

impl ToContractType for CircuitValidCommitmentsStatement {
    type ContractType = ValidCommitmentsStatement;

    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError> {
        Ok(Self::ContractType { indices: self.indices.to_contract_type()? })
    }
}

impl ToContractType for OrderValidityProofBundle {
    type ContractType = PartyMatchPayload;

    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError> {
        let commitments_statement = self.commitment_proof.statement.to_contract_type()?;
        let reblind_statement = self.reblind_proof.statement.clone().to_contract_type()?;
        Ok(Self::ContractType {
            validCommitmentsStatement: commitments_statement,
            validReblindStatement: reblind_statement,
        })
    }
}

impl ToContractType for SizedValidMatchSettleStatement {
    type ContractType = ValidMatchSettleStatement;

    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError> {
        Ok(Self::ContractType {
            firstPartyPublicShares: self
                .party0_modified_shares
                .to_scalars()
                .into_iter()
                .map(scalar_to_u256)
                .collect(),
            secondPartyPublicShares: self
                .party1_modified_shares
                .to_scalars()
                .into_iter()
                .map(scalar_to_u256)
                .collect(),
            firstPartySettlementIndices: self.party0_indices.to_contract_type()?,
            secondPartySettlementIndices: self.party1_indices.to_contract_type()?,
            protocolFeeRate: scalar_to_u256(self.protocol_fee.repr),
        })
    }
}

impl ToContractType for SizedValidMatchSettleWithCommitmentsStatement {
    type ContractType = ValidMatchSettleWithCommitmentsStatement;

    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError> {
        Ok(Self::ContractType {
            privateShareCommitment0: scalar_to_u256(self.private_share_commitment0),
            privateShareCommitment1: scalar_to_u256(self.private_share_commitment1),
            newShareCommitment0: scalar_to_u256(self.new_share_commitment0),
            newShareCommitment1: scalar_to_u256(self.new_share_commitment1),
            firstPartyPublicShares: self
                .party0_modified_shares
                .to_scalars()
                .into_iter()
                .map(scalar_to_u256)
                .collect(),
            secondPartyPublicShares: self
                .party1_modified_shares
                .to_scalars()
                .into_iter()
                .map(scalar_to_u256)
                .collect(),
            firstPartySettlementIndices: self.party0_indices.to_contract_type()?,
            secondPartySettlementIndices: self.party1_indices.to_contract_type()?,
            protocolFeeRate: scalar_to_u256(self.protocol_fee.repr),
        })
    }
}

impl ToContractType for SizedValidMatchSettleAtomicStatement {
    type ContractType = ValidMatchSettleAtomicStatement;

    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError> {
        Ok(Self::ContractType {
            matchResult: self.match_result.to_contract_type()?,
            externalPartyFees: self.external_party_fees.to_contract_type()?,
            internalPartyModifiedShares: self
                .internal_party_modified_shares
                .to_scalars()
                .into_iter()
                .map(scalar_to_u256)
                .collect(),
            internalPartySettlementIndices: self.internal_party_indices.to_contract_type()?,
            protocolFeeRate: scalar_to_u256(self.protocol_fee.repr),
            relayerFeeAddress: biguint_to_address(&self.relayer_fee_address)?,
        })
    }
}

impl ToContractType for SizedValidMalleableMatchSettleAtomicStatement {
    type ContractType = ValidMalleableMatchSettleAtomicStatement;

    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError> {
        Ok(Self::ContractType {
            matchResult: self.bounded_match_result.to_contract_type()?,
            internalPartyPublicShares: self
                .internal_party_public_shares
                .to_scalars()
                .into_iter()
                .map(scalar_to_u256)
                .collect(),
            externalFeeRates: self.external_fee_rates.to_contract_type()?,
            internalFeeRates: self.internal_fee_rates.to_contract_type()?,
            relayerFeeAddress: biguint_to_address(&self.relayer_fee_address)?,
        })
    }
}

impl ToContractType for SizedValidOfflineFeeSettlementStatement {
    type ContractType = ValidOfflineFeeSettlementStatement;

    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError> {
        let protocol_key_inner = self.protocol_key.to_contract_type()?;
        let protocol_key = EncryptionKey { point: protocol_key_inner };

        Ok(Self::ContractType {
            merkleRoot: scalar_to_u256(self.merkle_root),
            walletNullifier: scalar_to_u256(self.nullifier),
            newWalletCommitment: scalar_to_u256(self.new_wallet_commitment),
            updatedWalletPublicShares: self
                .updated_wallet_public_shares
                .to_scalars()
                .into_iter()
                .map(scalar_to_u256)
                .collect(),
            noteCiphertext: self.note_ciphertext.to_contract_type()?,
            noteCommitment: scalar_to_u256(self.note_commitment),
            protocolKey: protocol_key,
            isProtocolFee: self.is_protocol_fee,
        })
    }
}

impl ToContractType for SizedValidFeeRedemptionStatement {
    type ContractType = ValidFeeRedemptionStatement;

    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError> {
        Ok(Self::ContractType {
            walletRoot: scalar_to_u256(self.wallet_root),
            noteRoot: scalar_to_u256(self.note_root),
            walletNullifier: scalar_to_u256(self.wallet_nullifier),
            noteNullifier: scalar_to_u256(self.note_nullifier),
            newSharesCommitment: scalar_to_u256(self.new_shares_commitment),
            newWalletPublicShares: self
                .new_wallet_public_shares
                .to_scalars()
                .into_iter()
                .map(scalar_to_u256)
                .collect(),
            walletRootKey: self.recipient_root_key.to_contract_type()?,
        })
    }
}

// ---------------------
// | Application Types |
// ---------------------

impl ToContractType for CircuitExternalTransfer {
    type ContractType = ExternalTransfer;

    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError> {
        let transfer_type = match self.direction {
            ExternalTransferDirection::Deposit => 0,
            ExternalTransferDirection::Withdrawal => 1,
        };

        Ok(Self::ContractType {
            account: biguint_to_address(&self.account_addr)?,
            mint: biguint_to_address(&self.mint)?,
            amount: U256::from(self.amount),
            transferType: transfer_type,
        })
    }
}

impl ToContractType for CircuitTransferAuth {
    type ContractType = TransferAuthorization;

    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError> {
        match self {
            CircuitTransferAuth::Deposit(deposit_auth) => {
                let permit_sig = Bytes::from(deposit_auth.permit_signature.clone());
                let permit_deadline =
                    biguint_to_u256(&deposit_auth.permit_deadline).expect("invalid deadline");
                let permit_nonce =
                    biguint_to_u256(&deposit_auth.permit_nonce).expect("invalid nonce");

                Ok(Self::ContractType {
                    permit2Nonce: permit_nonce,
                    permit2Deadline: permit_deadline,
                    permit2Signature: permit_sig,
                    ..Default::default()
                })
            },
            CircuitTransferAuth::Withdrawal(withdrawal_auth) => Ok(Self::ContractType {
                externalTransferSignature: Bytes::from(
                    withdrawal_auth.external_transfer_signature.clone(),
                ),
                ..Default::default()
            }),
        }
    }
}

impl ToContractType for PublicSigningKey {
    type ContractType = PublicRootKey;

    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError> {
        let x_words = &self.x.scalar_words;
        let y_words = &self.y.scalar_words;
        let x = [scalar_to_u256(x_words[0]), scalar_to_u256(x_words[1])];
        let y = [scalar_to_u256(y_words[0]), scalar_to_u256(y_words[1])];

        Ok(Self::ContractType { x, y })
    }
}

impl ToContractType for CircuitOrderSettlementIndices {
    type ContractType = OrderSettlementIndices;

    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError> {
        Ok(Self::ContractType {
            balanceSend: U256::from(self.balance_send),
            balanceReceive: U256::from(self.balance_receive),
            order: U256::from(self.order),
        })
    }
}

impl ToCircuitType for OrderSettlementIndices {
    type CircuitType = CircuitOrderSettlementIndices;

    fn to_circuit_type(&self) -> Result<Self::CircuitType, DarkpoolClientError> {
        // Unwraps generally safe here because circuit constraints ensure the values are
        // `usize` coercible
        Ok(Self::CircuitType {
            balance_send: self.balanceSend.try_into().unwrap(),
            balance_receive: self.balanceReceive.try_into().unwrap(),
            order: self.order.try_into().unwrap(),
        })
    }
}

impl ToContractType for CircuitExternalMatchResult {
    type ContractType = ExternalMatchResult;

    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError> {
        Ok(Self::ContractType {
            quoteMint: biguint_to_address(&self.quote_mint)?,
            baseMint: biguint_to_address(&self.base_mint)?,
            quoteAmount: U256::from(self.quote_amount),
            baseAmount: U256::from(self.base_amount),
            direction: self.direction as u8,
        })
    }
}

impl ToCircuitType for ExternalMatchResult {
    type CircuitType = CircuitExternalMatchResult;

    fn to_circuit_type(&self) -> Result<Self::CircuitType, DarkpoolClientError> {
        Ok(Self::CircuitType {
            quote_mint: address_to_biguint(&self.quoteMint)?,
            base_mint: address_to_biguint(&self.baseMint)?,
            quote_amount: u256_to_amount(self.quoteAmount)?,
            base_amount: u256_to_amount(self.baseAmount)?,
            direction: self.direction == 1, // cast from u8 to bool
        })
    }
}

impl ToContractType for CircuitBoundedMatchResult {
    type ContractType = BoundedMatchResult;

    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError> {
        Ok(Self::ContractType {
            quoteMint: biguint_to_address(&self.quote_mint)?,
            baseMint: biguint_to_address(&self.base_mint)?,
            price: self.price.to_contract_type()?,
            minBaseAmount: U256::from(self.min_base_amount),
            maxBaseAmount: U256::from(self.max_base_amount),
            direction: self.direction as u8,
        })
    }
}

impl ToCircuitType for BoundedMatchResult {
    type CircuitType = CircuitBoundedMatchResult;

    fn to_circuit_type(&self) -> Result<Self::CircuitType, DarkpoolClientError> {
        Ok(Self::CircuitType {
            quote_mint: address_to_biguint(&self.quoteMint)?,
            base_mint: address_to_biguint(&self.baseMint)?,
            price: self.price.to_circuit_type()?,
            min_base_amount: u256_to_amount(self.minBaseAmount)?,
            max_base_amount: u256_to_amount(self.maxBaseAmount)?,
            direction: self.direction == 1, // cast from u8 to bool
        })
    }
}

impl ToContractType for CircuitFeeTake {
    type ContractType = FeeTake;

    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError> {
        Ok(Self::ContractType {
            relayerFee: U256::from(self.relayer_fee),
            protocolFee: U256::from(self.protocol_fee),
        })
    }
}

impl ToContractType for CircuitFeeTakeRate {
    type ContractType = FeeTakeRate;

    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError> {
        Ok(Self::ContractType {
            relayerFeeRate: self.relayer_fee_rate.to_contract_type()?,
            protocolFeeRate: self.protocol_fee_rate.to_contract_type()?,
        })
    }
}

impl ToCircuitType for FeeTakeRate {
    type CircuitType = CircuitFeeTakeRate;

    fn to_circuit_type(&self) -> Result<Self::CircuitType, DarkpoolClientError> {
        Ok(Self::CircuitType {
            relayer_fee_rate: self.relayerFeeRate.to_circuit_type()?,
            protocol_fee_rate: self.protocolFeeRate.to_circuit_type()?,
        })
    }
}

/// A type alias for a ciphertext sized to the `Note` type
type NoteCiphertext = CircuitElGamalCiphertext<NOTE_CIPHERTEXT_SIZE>;
impl ToContractType for NoteCiphertext {
    type ContractType = ElGamalCiphertext;

    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError> {
        Ok(Self::ContractType {
            ephemeralKey: self.ephemeral_key.to_contract_type()?,
            ciphertext: self.ciphertext.into_iter().map(scalar_to_u256).collect(),
        })
    }
}

impl ToContractType for CircuitFixedPoint {
    type ContractType = FixedPoint;

    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError> {
        Ok(Self::ContractType { repr: scalar_to_u256(self.repr) })
    }
}

impl ToCircuitType for FixedPoint {
    type CircuitType = CircuitFixedPoint;

    fn to_circuit_type(&self) -> Result<Self::CircuitType, DarkpoolClientError> {
        let repr = u256_to_scalar(self.repr);
        Ok(Self::CircuitType { repr })
    }
}

// ----------------------
// | Proof System Types |
// ----------------------

impl ToContractType for CircuitPlonkProof {
    type ContractType = PlonkProof;

    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError> {
        let evals = &self.poly_evals;
        let wire_comms =
            self.wires_poly_comms.iter().map(ToContractType::to_contract_type).try_collect()?;
        let quotient_comms = self
            .split_quot_poly_comms
            .iter()
            .map(ToContractType::to_contract_type)
            .try_collect()?;

        Ok(Self::ContractType {
            wire_comms: size_vec(wire_comms)?,
            z_comm: self.prod_perm_poly_comm.to_contract_type()?,
            quotient_comms: size_vec(quotient_comms)?,
            w_zeta: self.opening_proof.to_contract_type()?,
            w_zeta_omega: self.shifted_opening_proof.to_contract_type()?,
            wire_evals: size_vec(evals.wires_evals.iter().copied().map(fr_to_u256).collect())?,
            sigma_evals: size_vec(
                evals.wire_sigma_evals.iter().copied().map(fr_to_u256).collect(),
            )?,
            z_bar: fr_to_u256(evals.perm_next_eval),
        })
    }
}

impl ToContractType for CircuitPlonkLinkProof {
    type ContractType = LinkingProof;

    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError> {
        Ok(Self::ContractType {
            linking_quotient_poly_comm: self.quotient_commitment.to_contract_type()?,
            linking_poly_opening: self.opening_proof.proof.to_contract_type()?,
        })
    }
}

impl ToContractType for CircuitJubJubPoint {
    type ContractType = BabyJubJubPoint;

    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError> {
        Ok(Self::ContractType { x: scalar_to_u256(self.x), y: scalar_to_u256(self.y) })
    }
}

impl ToContractType for ark_bn254::G1Affine {
    type ContractType = G1Point;

    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError> {
        Ok(Self::ContractType { x: base_field_to_u256(self.x), y: base_field_to_u256(self.y) })
    }
}

impl ToContractType for PolynomialCommitment {
    type ContractType = G1Point;

    fn to_contract_type(&self) -> Result<Self::ContractType, DarkpoolClientError> {
        self.0.to_contract_type()
    }
}

// -----------
// | Helpers |
// -----------

/// Size a vector of values to be a known fixed size
pub fn size_vec<const N: usize, T>(vec: Vec<T>) -> Result<[T; N], DarkpoolClientError> {
    vec.try_into().map_err(|_| DarkpoolClientError::Conversion(ConversionError::InvalidLength))
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
