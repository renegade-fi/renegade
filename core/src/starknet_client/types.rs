//! Defines contract type bindings and helpers for interacting with them

use std::{
    convert::TryInto,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
};

use circuits::types::transfers::{
    ExternalTransfer as CircuitExternalTransfer, ExternalTransferDirection,
};
use crypto::fields::{biguint_to_starknet_felt, u128_to_starknet_felt};
use lazy_static::lazy_static;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use starknet::core::types::FieldElement as StarknetFieldElement;

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
