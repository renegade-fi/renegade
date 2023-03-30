//! The API module defines messaging interfaces between p2p nodes
#![deny(missing_docs)]

use num_bigint::BigUint;
use num_traits::Num;
use serde::{de::Error as DeserializeError, Deserialize, Deserializer, Serialize, Serializer};

pub mod http;
pub mod types;
pub mod websocket;

/// An empty request/response type
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct EmptyRequestResponse;

/// A helper to serialize a BigUint to a hex string
pub fn biguint_to_hex_string<S>(val: &BigUint, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&val.to_str_radix(16 /* radix */))
}

/// A helper to deserialize a BigUint from a hex string
pub fn biguint_from_hex_string<'de, D>(d: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    // Deserialize as a string and remove "0x" if present
    let hex_string = String::deserialize(d)?;
    let hex_string = hex_string.strip_prefix("0x").unwrap_or(&hex_string);

    BigUint::from_str_radix(hex_string, 16 /* radix */).map_err(|e| {
        DeserializeError::custom(format!("error deserializing BigUint from hex string: {e}"))
    })
}
