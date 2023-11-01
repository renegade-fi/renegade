//! Defines contract type bindings and helpers for interacting with them

use std::{
    convert::TryInto,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    iter,
};

use circuit_types::{
    traits::BaseType,
    transfers::{ExternalTransfer as CircuitExternalTransfer, ExternalTransferDirection},
};
use lazy_static::lazy_static;
use mpc_bulletproof::{r1cs::R1CSProof, InnerProductProof};
use mpc_stark::algebra::{scalar::Scalar, stark_curve::StarkPoint};
use num_bigint::BigUint;
use renegade_crypto::fields::{
    biguint_to_starknet_felt, scalar_to_starknet_felt, starknet_felt_to_biguint,
    starknet_felt_to_scalar, starknet_felt_to_usize, u128_to_starknet_felt,
};
use serde::{Deserialize, Serialize};
use starknet::core::types::FieldElement as StarknetFieldElement;

use crate::error::StarknetClientError;

/// The error message emitted when the end of the calldata is reached before
/// deserialization is complete
const ERR_CALLDATA_END: &str = "end of calldata reached before deserialization complete";

lazy_static! {
    /// The bit mask for the lower 128 bits of a U256
    static ref LOW_BIT_MASK: BigUint = (BigUint::from(1u8) << 128) - 1u8;
}

/// An external transfer tuple represents either a deposit or withdraw
/// to/from the darkpool
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalTransfer {
    /// The account contract address to deposit from or withdraw to
    pub sender_address: BigUint,
    /// The contract address of the ERC-20 token to deposit/withdraw
    pub mint: BigUint,
    /// The amount of the mint token to deposit/withdraw
    pub amount: StarknetU256,
    /// The direction of the transfer
    pub direction: ExternalTransferDirection,
}

impl ExternalTransfer {
    /// Constructor
    pub fn new(
        sender_address: BigUint,
        mint: BigUint,
        amount: BigUint,
        direction: ExternalTransferDirection,
    ) -> Self {
        Self {
            sender_address,
            mint,
            amount: amount.into(),
            direction,
        }
    }
}

impl From<CircuitExternalTransfer> for ExternalTransfer {
    fn from(transfer: CircuitExternalTransfer) -> Self {
        ExternalTransfer {
            sender_address: transfer.account_addr,
            mint: transfer.mint,
            amount: transfer.amount.into(),
            direction: transfer.direction,
        }
    }
}

/// A serialization implementation in the format that the Starknet client
/// expects
impl From<ExternalTransfer> for Vec<StarknetFieldElement> {
    fn from(transfer: ExternalTransfer) -> Self {
        // The amount is serialized as a U256, which is represented by two
        // starknet felts
        let amount_felts: Vec<StarknetFieldElement> = transfer.amount.into();

        vec![
            biguint_to_starknet_felt(&transfer.sender_address),
            biguint_to_starknet_felt(&transfer.mint),
            amount_felts[0],
            amount_felts[1],
            StarknetFieldElement::from(transfer.direction as u8),
        ]
    }
}

/// A single party's state validity proof bundle used as input to the matching
/// engine and forwarded to the contract for verification
#[derive(Clone)]
pub struct MatchPayload {
    /// The public share of the new wallet's blinder
    pub wallet_blinder_share: Scalar,
    /// The nullifier of the old shares before reblinding
    pub old_shares_nullifier: Scalar,
    /// The commitment to the new wallet's private shares
    pub wallet_share_commitment: Scalar,
    /// The public shares of the new, reblinded wallet
    pub public_wallet_shares: Vec<Scalar>,
    /// The proof of `VALID COMMITMENTS` for the new wallet
    pub valid_commitments_proof: R1CSProof,
    /// The commitments to the witness data for the `VALID COMMITMENTS` proof
    pub valid_commitments_witness_commitments: Vec<StarkPoint>,
    /// The proof of `VALID REBLIND` for the new wallet
    pub valid_reblind_proof: R1CSProof,
    /// The commitments to the witness data for the `VALID REBLIND` proof
    pub valid_reblind_witness_commitments: Vec<StarkPoint>,
}

/// Represents the U256 type in Starknet
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct StarknetU256 {
    /// The low 128 bits of the represented integer
    pub low: u128,
    /// The high 128 bits of the represented integer
    pub high: u128,
}

impl From<BigUint> for StarknetU256 {
    fn from(val: BigUint) -> Self {
        let low_mask = &val & &*LOW_BIT_MASK;
        let low: u128 = low_mask.try_into().unwrap();
        let high: u128 = (val >> 128u32).try_into().unwrap();

        Self { low, high }
    }
}

impl From<StarknetU256> for BigUint {
    fn from(val: StarknetU256) -> Self {
        let low_bigint = BigUint::from(val.low);
        let high_bigint = BigUint::from(val.high);

        (high_bigint << 128) + low_bigint
    }
}

impl Debug for StarknetU256 {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        <Self as Display>::fmt(self, f)
    }
}

impl Display for StarknetU256 {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let self_bigint: BigUint = (*self).into();
        write!(f, "{self_bigint}")
    }
}

impl From<StarknetU256> for Vec<StarknetFieldElement> {
    fn from(val: StarknetU256) -> Self {
        let low_felt = u128_to_starknet_felt(val.low);
        let high_felt = u128_to_starknet_felt(val.high);

        vec![low_felt, high_felt]
    }
}

// --------------------------
// | Calldata Serialization |
// --------------------------

/// Implementing types may be serialized into `Starknet` calldata, i.e. a vector
/// of `FieldElement`s
///
/// Borrowed from https://github.com/renegade-fi/renegade-contracts/blob/main/tests/src/utils.rs#L357
pub trait CalldataSerializable {
    /// Serializes the type into a vector of `FieldElement`s
    fn to_calldata(&self) -> Vec<StarknetFieldElement>;
}

/// Implementing types may be deserialized from `Starknet` calldata, i.e. a
/// vector of `FieldElement`s
pub trait CalldataDeserializable<I: Iterator<Item = StarknetFieldElement>>: Sized {
    /// Deserializes the type from a vector of `FieldElement`s  
    fn from_calldata(i: &mut I) -> Result<Self, StarknetClientError>;
}

impl CalldataSerializable for Scalar {
    fn to_calldata(&self) -> Vec<StarknetFieldElement> {
        vec![scalar_to_starknet_felt(self)]
    }
}

impl<I: Iterator<Item = StarknetFieldElement>> CalldataDeserializable<I> for Scalar {
    fn from_calldata(i: &mut I) -> Result<Self, StarknetClientError> {
        let felt = i
            .next()
            .ok_or_else(|| StarknetClientError::Serde(ERR_CALLDATA_END.to_string()))?;
        Ok(starknet_felt_to_scalar(&felt))
    }
}

impl CalldataSerializable for Vec<Scalar> {
    fn to_calldata(&self) -> Vec<StarknetFieldElement> {
        // Prepend the length to the result
        let mut calldata = vec![StarknetFieldElement::from(self.len())];
        calldata.extend(self.iter().flat_map(|s| s.to_calldata()));

        calldata
    }
}

impl<I: Iterator<Item = StarknetFieldElement>> CalldataDeserializable<I> for Vec<Scalar> {
    fn from_calldata(i: &mut I) -> Result<Self, StarknetClientError> {
        let len = starknet_felt_to_usize(
            &i.next()
                .ok_or_else(|| StarknetClientError::Serde(ERR_CALLDATA_END.to_string()))?,
        );

        let mut scalars = Vec::with_capacity(len);
        for _ in 0..len {
            scalars.push(Scalar::from_calldata(i)?);
        }

        Ok(scalars)
    }
}

impl CalldataSerializable for BigUint {
    fn to_calldata(&self) -> Vec<StarknetFieldElement> {
        vec![biguint_to_starknet_felt(self)]
    }
}

impl<I: Iterator<Item = StarknetFieldElement>> CalldataDeserializable<I> for BigUint {
    fn from_calldata(i: &mut I) -> Result<Self, StarknetClientError> {
        let felt = i
            .next()
            .ok_or_else(|| StarknetClientError::Serde(ERR_CALLDATA_END.to_string()))?;
        Ok(starknet_felt_to_biguint(&felt))
    }
}

impl CalldataSerializable for StarkPoint {
    fn to_calldata(&self) -> Vec<StarknetFieldElement> {
        if self.is_identity() {
            vec![StarknetFieldElement::ZERO, StarknetFieldElement::ZERO]
        } else {
            let aff = self.to_affine();
            vec![
                biguint_to_starknet_felt(&aff.x.into()),
                biguint_to_starknet_felt(&aff.y.into()),
            ]
        }
    }
}

impl<I: Iterator<Item = StarknetFieldElement>> CalldataDeserializable<I> for StarkPoint {
    fn from_calldata(i: &mut I) -> Result<Self, StarknetClientError> {
        // Parse the affine coordinates of the point
        let x = BigUint::from_calldata(i)?;
        let y = BigUint::from_calldata(i)?;

        Ok(StarkPoint::from_affine_coords(x, y))
    }
}

impl CalldataSerializable for Vec<StarkPoint> {
    fn to_calldata(&self) -> Vec<StarknetFieldElement> {
        // Prepend the length
        let mut calldata = vec![StarknetFieldElement::from(self.len())];
        calldata.extend(self.iter().flat_map(|p| p.to_calldata()));

        calldata
    }
}

impl<I: Iterator<Item = StarknetFieldElement>> CalldataDeserializable<I> for Vec<StarkPoint> {
    fn from_calldata(i: &mut I) -> Result<Self, StarknetClientError> {
        let len = starknet_felt_to_usize(
            &i.next()
                .ok_or_else(|| StarknetClientError::Serde(ERR_CALLDATA_END.to_string()))?,
        );

        let mut points = Vec::with_capacity(len);
        for _ in 0..len {
            points.push(StarkPoint::from_calldata(i)?);
        }

        Ok(points)
    }
}

impl CalldataSerializable for StarknetU256 {
    fn to_calldata(&self) -> Vec<StarknetFieldElement> {
        vec![
            StarknetFieldElement::from(self.low),
            StarknetFieldElement::from(self.high),
        ]
    }
}

impl CalldataSerializable for R1CSProof {
    fn to_calldata(&self) -> Vec<StarknetFieldElement> {
        [
            self.A_I1, self.A_O1, self.S1, self.T_1, self.T_3, self.T_4, self.T_5, self.T_6,
        ]
        .iter()
        .flat_map(|p| p.to_calldata())
        .chain(
            [self.t_x, self.t_x_blinding, self.e_blinding]
                .iter()
                .map(scalar_to_starknet_felt),
        )
        .chain(iter::once(StarknetFieldElement::from(
            self.ipp_proof.L_vec.len(),
        )))
        .chain(self.ipp_proof.L_vec.iter().flat_map(|p| p.to_calldata()))
        .chain(iter::once(StarknetFieldElement::from(
            self.ipp_proof.R_vec.len(),
        )))
        .chain(self.ipp_proof.R_vec.iter().flat_map(|p| p.to_calldata()))
        .chain(
            [self.ipp_proof.a, self.ipp_proof.b]
                .iter()
                .map(scalar_to_starknet_felt),
        )
        .collect()
    }
}

impl<I: Iterator<Item = StarknetFieldElement>> CalldataDeserializable<I> for R1CSProof {
    fn from_calldata(i: &mut I) -> Result<Self, StarknetClientError> {
        Ok(R1CSProof {
            A_I1: StarkPoint::from_calldata(i)?,
            A_O1: StarkPoint::from_calldata(i)?,
            S1: StarkPoint::from_calldata(i)?,
            // The contract does not allow second phase commitments, so we assume that these values
            // are the identity
            A_I2: StarkPoint::identity(),
            A_O2: StarkPoint::identity(),
            S2: StarkPoint::identity(),
            T_1: StarkPoint::from_calldata(i)?,
            T_3: StarkPoint::from_calldata(i)?,
            T_4: StarkPoint::from_calldata(i)?,
            T_5: StarkPoint::from_calldata(i)?,
            T_6: StarkPoint::from_calldata(i)?,
            t_x: Scalar::from_calldata(i)?,
            t_x_blinding: Scalar::from_calldata(i)?,
            e_blinding: Scalar::from_calldata(i)?,
            ipp_proof: InnerProductProof {
                L_vec: Vec::from_calldata(i)?,
                R_vec: Vec::from_calldata(i)?,
                a: Scalar::from_calldata(i)?,
                b: Scalar::from_calldata(i)?,
            },
        })
    }
}

impl CalldataSerializable for ExternalTransferDirection {
    fn to_calldata(&self) -> Vec<StarknetFieldElement> {
        vec![StarknetFieldElement::from(*self as u8)]
    }
}

impl<I: Iterator<Item = StarknetFieldElement>> CalldataDeserializable<I>
    for ExternalTransferDirection
{
    fn from_calldata(i: &mut I) -> Result<Self, StarknetClientError> {
        let scalar = Scalar::from_calldata(i)?;
        Ok(ExternalTransferDirection::from_scalars(
            &mut vec![scalar].into_iter(),
        ))
    }
}

impl CalldataSerializable for ExternalTransfer {
    fn to_calldata(&self) -> Vec<StarknetFieldElement> {
        let mut calldata = self.sender_address.to_calldata();
        calldata.extend(self.mint.to_calldata());
        calldata.extend(self.amount.to_calldata());
        calldata.extend(self.direction.to_calldata());

        calldata
    }
}

impl CalldataSerializable for MatchPayload {
    fn to_calldata(&self) -> Vec<StarknetFieldElement> {
        [
            self.wallet_blinder_share,
            self.old_shares_nullifier,
            self.wallet_share_commitment,
        ]
        .iter()
        .map(scalar_to_starknet_felt)
        .chain(iter::once(StarknetFieldElement::from(
            self.public_wallet_shares.len(),
        )))
        .chain(
            self.public_wallet_shares
                .iter()
                .map(scalar_to_starknet_felt),
        )
        .chain(self.valid_commitments_proof.to_calldata())
        .chain(iter::once(StarknetFieldElement::from(
            self.valid_commitments_witness_commitments.len(),
        )))
        .chain(
            self.valid_commitments_witness_commitments
                .iter()
                .flat_map(|p| p.to_calldata()),
        )
        .chain(self.valid_reblind_proof.to_calldata())
        .chain(iter::once(StarknetFieldElement::from(
            self.valid_reblind_witness_commitments.len(),
        )))
        .chain(
            self.valid_reblind_witness_commitments
                .iter()
                .flat_map(|p| p.to_calldata()),
        )
        .collect()
    }
}

impl<I: Iterator<Item = StarknetFieldElement>> CalldataDeserializable<I> for MatchPayload {
    fn from_calldata(i: &mut I) -> Result<Self, StarknetClientError> {
        Ok(MatchPayload {
            wallet_blinder_share: Scalar::from_calldata(i)?,
            old_shares_nullifier: Scalar::from_calldata(i)?,
            wallet_share_commitment: Scalar::from_calldata(i)?,
            public_wallet_shares: Vec::from_calldata(i)?,
            valid_commitments_proof: R1CSProof::from_calldata(i)?,
            valid_commitments_witness_commitments: Vec::from_calldata(i)?,
            valid_reblind_proof: R1CSProof::from_calldata(i)?,
            valid_reblind_witness_commitments: Vec::from_calldata(i)?,
        })
    }
}
