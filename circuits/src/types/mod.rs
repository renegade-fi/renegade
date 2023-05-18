//! Groups type definitions and abstractions useful in the circuitry

use bigdecimal::Num;
use crypto::fields::{biguint_to_scalar, scalar_to_biguint};
use curve25519_dalek::scalar::Scalar;
use num_bigint::BigUint;
use serde::{de::Error as SerdeErr, Deserialize, Deserializer, Serialize, Serializer};
pub mod balance;
// pub mod fee;
// pub mod handshake_tuple;
// pub mod keychain;
// pub mod r#match;
// pub mod note;
// pub mod order;
// pub mod transfers;
// pub mod wallet;

// -----------------------------------------
// | Serialization Deserialization Helpers |
// -----------------------------------------

/// A helper to serialize a Scalar to a hex string
pub fn scalar_to_hex_string<S>(val: &Scalar, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    biguint_to_hex_string(&scalar_to_biguint(val), s)
}

/// A helper to deserialize a Scalar from a hex string
pub fn scalar_from_hex_string<'de, D>(d: D) -> Result<Scalar, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(biguint_to_scalar(&biguint_from_hex_string(d)?))
}

/// A helper to serialize a BigUint to a hex string
pub fn biguint_to_hex_string<S>(val: &BigUint, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&format!("0x{}", val.to_str_radix(16 /* radix */)))
}

/// A helper to deserialize a BigUint from a hex string
pub fn biguint_from_hex_string<'de, D>(d: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    // Deserialize as a string and remove "0x" if present
    let hex_string = String::deserialize(d)?;
    let hex_string = hex_string.strip_prefix("0x").unwrap_or(&hex_string);

    BigUint::from_str_radix(hex_string, 16 /* radix */)
        .map_err(|e| SerdeErr::custom(format!("error deserializing BigUint from hex string: {e}")))
}

/// A helper for serializing array types
pub(crate) fn serialize_array<const ARR_SIZE: usize, T, S>(
    arr: &[T; ARR_SIZE],
    s: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize + Clone,
    [(); ARR_SIZE]: Sized,
{
    // Convert the array to a vec
    let arr_vec: Vec<T> = arr.clone().into();
    arr_vec.serialize(s)
}

/// A helper for deserializing array types
pub(crate) fn deserialize_array<'de, const ARR_SIZE: usize, T, D>(
    d: D,
) -> Result<[T; ARR_SIZE], D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
    [(); ARR_SIZE]: Sized,
{
    // Deserialize a vec and then convert to an array
    let deserialized_vec: Vec<T> = Vec::deserialize(d)?;
    deserialized_vec
        .try_into()
        .map_err(|_| SerdeErr::custom("incorrect size of serialized array"))
}
