//! Utilities for converting between circuit types such as statements and
//! proofs, and their analogues as expected by the smart contracts.

use alloy_primitives::{Address, U160, U256};
use ark_bn254::g1::Config as G1Config;
use ark_ec::short_weierstrass::Affine;
use circuit_types::Amount;
use constants::Scalar;
use num_bigint::BigUint;

use crate::errors::ConversionError;

/// Type alias for the affine representation of the
/// system curve's G1 group
pub type G1Affine = Affine<G1Config>;

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
    // Take the LSBs of the `U256`
    let le_bytes = u256.to_le_bytes_vec();
    let trimmed: [u8; 16] = le_bytes[..16].try_into().unwrap();
    let amount = Amount::from_le_bytes(trimmed);
    Ok(amount)
}

/// Converts a `Scalar` to a `U256`
pub fn scalar_to_u256(scalar: Scalar) -> U256 {
    U256::from_be_slice(&scalar.to_bytes_be())
}

/// Converts an alloy `U256` to a `Scalar`
pub fn u256_to_scalar(u256: U256) -> Scalar {
    let bytes = u256.to_be_bytes_vec();
    Scalar::from_be_bytes_mod_order(&bytes)
}
