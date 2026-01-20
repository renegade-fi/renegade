//! Helpers for converting values to and from hex strings
//!
//! This module provides two levels of functionality:
//! - `hex-core` feature: Lightweight biguint/bytes hex conversions (no circuit
//!   deps)
//! - `hex` feature: Full hex utilities including scalar/jubjub conversions

use std::str::FromStr;

use alloy::primitives::Address;
#[cfg(feature = "hex")]
use ark_ec::{CurveGroup, twisted_edwards::Projective};
#[cfg(feature = "hex")]
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
#[cfg(feature = "hex")]
use circuit_types::primitives::baby_jubjub::BabyJubJubPoint;
#[cfg(feature = "hex")]
use constants::{EmbeddedCurveConfig, EmbeddedScalarField, Scalar};
#[cfg(feature = "hex")]
use crypto::fields::{biguint_to_jubjub, biguint_to_scalar, jubjub_to_biguint, scalar_to_biguint};
use num_bigint::BigUint;
use num_traits::Num;

#[cfg(feature = "hex")]
use crate::raw_err_str;

/// The byte length of an Ethereum address (inlined to avoid constants dep for
/// hex-core)
const ADDRESS_BYTE_LENGTH: usize = 20;

/// Convert a byte array to a hex string
pub fn bytes_to_hex_string(bytes: &[u8]) -> String {
    let encoded = hex::encode(bytes);
    format!("0x{encoded}")
}

/// Convert a hex string to a byte array
pub fn bytes_from_hex_string(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    hex::decode(hex).map_err(|e| format!("error deserializing bytes from hex string: {e}"))
}

/// A helper to serialize a BigUint to a hex string
pub fn biguint_to_hex_string(val: &BigUint) -> String {
    format!("0x{}", val.to_str_radix(16 /* radix */))
}

/// Convert an address to a hex string
pub fn address_to_hex_string(addr: &Address) -> String {
    format!("{addr:#x}")
}

/// Convert a hex string to an address
pub fn address_from_hex_string(hex: &str) -> Result<Address, String> {
    Address::from_str(hex).map_err(|e| format!("error deserializing address from hex string: {e}"))
}

/// From a BigUint, get a lowercase hex string with a 0x prefix, padded to the
/// Ethereum address length
pub fn biguint_to_hex_addr(val: &BigUint) -> String {
    let mut bytes = [0_u8; ADDRESS_BYTE_LENGTH];
    let val_bytes = val.to_bytes_be();

    let len = val_bytes.len();
    debug_assert!(len <= ADDRESS_BYTE_LENGTH, "BigUint too large for an address");

    bytes[ADDRESS_BYTE_LENGTH - val_bytes.len()..].copy_from_slice(&val_bytes);
    let hex_str = hex::encode(bytes);
    format!("0x{hex_str}")
}

/// A helper to deserialize a BigUint from a hex string
pub fn biguint_from_hex_string(hex: &str) -> Result<BigUint, String> {
    // Deserialize as a string and remove "0x" if present
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    BigUint::from_str_radix(stripped, 16 /* radix */)
        .map_err(|e| format!("error deserializing BigUint from hex string: {e}"))
}

// --- Full hex feature functions (require circuit deps) --- //

/// A helper to serialize a scalar to a hex string
#[cfg(feature = "hex")]
pub fn scalar_to_hex_string(val: &Scalar) -> String {
    let biguint = scalar_to_biguint(val);
    biguint_to_hex_string(&biguint)
}

/// A helper to deserialize a scalar from a hex string
#[cfg(feature = "hex")]
pub fn scalar_from_hex_string(hex: &str) -> Result<Scalar, String> {
    let biguint = biguint_from_hex_string(hex)?;
    Ok(biguint_to_scalar(&biguint))
}

/// A helper to serialize an EmbeddedScalarField to a hex string
#[cfg(feature = "hex")]
pub fn embedded_scalar_to_hex_string(val: &EmbeddedScalarField) -> String {
    let biguint = jubjub_to_biguint(*val);
    biguint_to_hex_string(&biguint)
}

/// A helper to deserialize an EmbeddedScalarField from a hex string
#[cfg(feature = "hex")]
pub fn embedded_scalar_from_hex_string(hex: &str) -> Result<EmbeddedScalarField, String> {
    let biguint = biguint_from_hex_string(hex)?;
    Ok(biguint_to_jubjub(&biguint))
}

/// A helper to serialize an EmbeddedScalarField to a decimal string
#[cfg(feature = "hex")]
pub fn embedded_scalar_to_decimal_string(val: &EmbeddedScalarField) -> String {
    let biguint = jubjub_to_biguint(*val);
    biguint.to_string()
}

/// A helper to deserialize an EmbeddedScalarField from a decimal string
#[cfg(feature = "hex")]
pub fn embedded_scalar_from_decimal_string(decimal: &str) -> Result<EmbeddedScalarField, String> {
    let biguint = BigUint::from_str_radix(decimal, 10 /* radix */)
        .map_err(|e| format!("error deserializing BigUint from decimal string: {e}"))?;
    Ok(biguint_to_jubjub(&biguint))
}

/// Convert a Baby-JubJub point to a hex string
#[cfg(feature = "hex")]
pub fn jubjub_to_hex_string(point: &BabyJubJubPoint) -> String {
    let converted_point = Projective::<EmbeddedCurveConfig>::from(*point);
    let mut bytes = vec![];
    converted_point.into_affine().serialize_uncompressed(&mut bytes).unwrap();

    format!("0x{}", hex::encode(bytes))
}

/// Deserialize a Baby-JubJub point from a hex string
#[cfg(feature = "hex")]
pub fn jubjub_from_hex_string(hex: &str) -> Result<BabyJubJubPoint, String> {
    // Deserialize as a string and remove "0x" if present
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(stripped)
        .map_err(|e| format!("error deserializing bytes from hex string: {e}"))?;

    let projective = Projective::<EmbeddedCurveConfig>::deserialize_uncompressed(bytes.as_slice())
        .map_err(raw_err_str!("error deserializing projective point from bytes: {:?}"))?;
    Ok(projective.into())
}

#[cfg(test)]
mod tests {
    use alloy::primitives::Address;
    use rand::{RngCore, thread_rng};

    use super::*;

    #[test]
    fn test_bytes_serialize_deserialize() {
        let mut rng = thread_rng();
        let mut bytes = [0_u8; 32];
        rng.fill_bytes(&mut bytes);

        let hex = bytes_to_hex_string(&bytes);
        let bytes_rec = bytes_from_hex_string(&hex).unwrap();

        assert_eq!(bytes.to_vec(), bytes_rec)
    }

    #[test]
    fn test_address_serialize_deserialize() {
        // Build a random address
        let mut rng = thread_rng();
        let mut bytes = [0_u8; 20];
        rng.fill_bytes(&mut bytes);
        let addr = Address::from(bytes);

        // Serialize and deserialize
        let hex = address_to_hex_string(&addr);
        let addr_rec = address_from_hex_string(&hex).unwrap();
        assert_eq!(addr, addr_rec);
    }
}
