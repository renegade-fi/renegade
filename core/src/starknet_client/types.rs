//! Defines contract type bindings and helpers for interacting with them

use std::{
    convert::TryInto,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    io::Cursor,
};

use circuits::{
    traits::CircuitCommitmentType,
    types::transfers::{ExternalTransfer as CircuitExternalTransfer, ExternalTransferDirection},
};
use crypto::fields::{biguint_to_starknet_felt, u128_to_starknet_felt};
use lazy_static::lazy_static;
use mpc_bulletproof::r1cs::R1CSProof;
use mpc_stark::algebra::{
    scalar::SCALAR_BYTES,
    stark_curve::{StarkPoint, STARK_POINT_BYTES},
};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use starknet::core::types::FieldElement as StarknetFieldElement;

use crate::proof_generation::jobs::ProofBundle;

use super::helpers::{
    read_point, read_scalar, serialize_points_to_calldata, serialize_scalars_to_calldata,
};

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

/// A serialization implementation in the format that the Starknet client expects
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

/// Represents the U256 type in Starknet
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct StarknetU256 {
    /// The low 128 bits of the represented integer
    low: u128,
    /// The high 128 bits of the represented integer
    high: u128,
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

// ---------------------------------------
// | Proof bundle calldata serialization |
// ---------------------------------------

pub(super) trait CalldataSerializable {
    fn to_calldata(&self) -> Result<Vec<StarknetFieldElement>, String>;
}

impl CalldataSerializable for R1CSProof {
    #[allow(non_snake_case)]
    fn to_calldata(&self) -> Result<Vec<StarknetFieldElement>, String> {
        // This mirrors the implementations of `R1CSProof::from_bytes` and
        // `InnerProductProof::from_bytes` in the mpc-bulletproof crate

        let proof_bytes = self.to_bytes();
        let mut proof_bytes_cursor = Cursor::new(proof_bytes.as_slice());

        let A_I1 = read_point(&mut proof_bytes_cursor)?;
        let A_O1 = read_point(&mut proof_bytes_cursor)?;
        let S1 = read_point(&mut proof_bytes_cursor)?;
        let T_1 = read_point(&mut proof_bytes_cursor)?;
        let T_3 = read_point(&mut proof_bytes_cursor)?;
        let T_4 = read_point(&mut proof_bytes_cursor)?;
        let T_5 = read_point(&mut proof_bytes_cursor)?;
        let T_6 = read_point(&mut proof_bytes_cursor)?;
        let t_hat = read_scalar(&mut proof_bytes_cursor)?;
        let t_blind = read_scalar(&mut proof_bytes_cursor)?;
        let e_blind = read_scalar(&mut proof_bytes_cursor)?;

        // IPP consists of L, R vectors & a, b scalars.
        // L, R vectors have log2(n) elements each (where n is the number of multiplication gates)
        // Thus, log2(n) = ((# remaining bytes - 2 * bytes_per_scalar) / bytes_per_point) / 2
        let ipp_bytes_size = proof_bytes.len() - proof_bytes_cursor.position() as usize;
        let lg_n = ((ipp_bytes_size - 2 * SCALAR_BYTES) / STARK_POINT_BYTES) / 2;

        let mut L: Vec<StarkPoint> = Vec::with_capacity(lg_n);
        let mut R: Vec<StarkPoint> = Vec::with_capacity(lg_n);
        for i in 0..lg_n {
            let l_point = read_point(&mut proof_bytes_cursor)?;
            let r_point = read_point(&mut proof_bytes_cursor)?;
            L.push(l_point);
            R.push(r_point);
        }

        let a = read_scalar(&mut proof_bytes_cursor)?;
        let b = read_scalar(&mut proof_bytes_cursor)?;

        // A_I1..T_6 is 8 points, 2 felts per point
        // t_hat..e_blind, a & b is 5 scalars, 1 felt per scalar
        let mut felts = Vec::with_capacity(2 * 8 + 2 * 2 * L.len() + 5);

        serialize_points_to_calldata(&[A_I1, A_O1, S1, T_1, T_3, T_4, T_5, T_6], &mut felts);

        serialize_scalars_to_calldata(&[t_hat, t_blind, e_blind], &mut felts);

        // Need to serialize array length first before the elements

        let lg_n_felt = StarknetFieldElement::from(L.len());

        felts.push(lg_n_felt);
        serialize_points_to_calldata(&L, &mut felts);

        felts.push(lg_n_felt);
        serialize_points_to_calldata(&R, &mut felts);

        serialize_scalars_to_calldata(&[a, b], &mut felts);

        Ok(felts)
    }
}

impl CalldataSerializable for ProofBundle {
    fn to_calldata(&self) -> Result<Vec<StarknetFieldElement>, String> {
        let mut felts = Vec::new();

        match self {
            ProofBundle::ValidWalletCreate(b) => {
                felts.extend(b.proof.to_calldata()?);
                serialize_points_to_calldata(&b.commitment.to_commitments(), &mut felts);
            }
            ProofBundle::ValidReblind(b) => {
                felts.extend(b.proof.to_calldata()?);
                serialize_points_to_calldata(&b.commitment.to_commitments(), &mut felts);
            }
            ProofBundle::ValidCommitments(b) => {
                felts.extend(b.proof.to_calldata()?);
                serialize_points_to_calldata(&b.commitment.to_commitments(), &mut felts);
            }
            ProofBundle::ValidWalletUpdate(b) => {
                felts.extend(b.proof.to_calldata()?);
                serialize_points_to_calldata(&b.commitment.to_commitments(), &mut felts);
            }
            ProofBundle::ValidMatchMpc(b) => {
                felts.extend(b.proof.to_calldata()?);
                serialize_points_to_calldata(&b.commitment.to_commitments(), &mut felts);
            }
            ProofBundle::ValidSettle(b) => {
                felts.extend(b.proof.to_calldata()?);
                serialize_points_to_calldata(&b.commitment.to_commitments(), &mut felts);
            }
        };

        Ok(felts)
    }
}
