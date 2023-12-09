//! Helpers for converting values to and from hex strings
use circuit_types::keychain::{NonNativeScalar, PublicSigningKey};
use constants::Scalar;
use num_bigint::BigUint;
use num_traits::Num;
use renegade_crypto::fields::{biguint_to_scalar, scalar_to_biguint};

/// A helper to serialize a BigUint to a hex string
pub fn biguint_to_hex_string(val: &BigUint) -> String {
    format!("0x{}", val.to_str_radix(16 /* radix */))
}

/// A helper to deserialize a BigUint from a hex string
pub fn biguint_from_hex_string(hex: &str) -> Result<BigUint, String> {
    // Deserialize as a string and remove "0x" if present
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    BigUint::from_str_radix(stripped, 16 /* radix */)
        .map_err(|e| format!("error deserializing BigUint from hex string: {e}"))
}

/// A helper to serialize a scalar to a hex string
pub fn scalar_to_hex_string(val: &Scalar) -> String {
    let biguint = scalar_to_biguint(val);
    biguint_to_hex_string(&biguint)
}

/// A helper to deserialize a scalar from a hex string
pub fn scalar_from_hex_string(hex: &str) -> Result<Scalar, String> {
    let biguint = biguint_from_hex_string(hex)?;
    Ok(biguint_to_scalar(&biguint))
}

/// A helper to serialize a nonnative scalar to a hex string
pub fn nonnative_scalar_to_hex_string<const NUM_WORDS: usize>(
    val: &NonNativeScalar<NUM_WORDS>,
) -> String {
    biguint_to_hex_string(&val.into())
}

/// A helper method to deserialize a nonnative scalar from a hex string
pub fn nonnative_scalar_from_hex_string<const NUM_WORDS: usize>(
    hex: &str,
) -> Result<NonNativeScalar<NUM_WORDS>, String> {
    let biguint = biguint_from_hex_string(hex)?;
    Ok(NonNativeScalar::from(&biguint))
}

/// A helper to serialize a signing key to a hex string
pub fn public_sign_key_to_hex_string(val: &PublicSigningKey) -> String {
    let bytes = val.to_compressed_bytes();
    format!("0x{}", hex::encode(bytes))
}

/// A helper to deserialize a signing key from a hex string
pub fn public_sign_key_from_hex_string(hex: &str) -> Result<PublicSigningKey, String> {
    // Deserialize as a string and remove "0x" if present
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(stripped)
        .map_err(|e| format!("error deserializing bytes from hex string: {e}"))?;

    PublicSigningKey::from_bytes(&bytes)
        .map_err(|e| format!("error deserializing signing key from bytes: {e}"))
}
