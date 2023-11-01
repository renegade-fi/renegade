//! The API module defines messaging interfaces between p2p nodes
#![deny(missing_docs)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use num_bigint::BigUint;
use num_traits::Num;
use serde::{de::Error as DeserializeError, Deserialize, Deserializer, Serialize, Serializer};

pub mod bus_message;
pub mod http;
pub mod types;
pub mod websocket;

/// An empty request/response type
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmptyRequestResponse {}

/// Serialize an empty request/response
impl Serialize for EmptyRequestResponse {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_none()
    }
}

/// Deserialize an empty request/response
impl<'de> Deserialize<'de> for EmptyRequestResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_unit(EmptyRequestResponseVisitor)
    }
}

/// Visitor for deserializing an empty request/response
struct EmptyRequestResponseVisitor;
impl<'de> serde::de::Visitor<'de> for EmptyRequestResponseVisitor {
    type Value = EmptyRequestResponse;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("null")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(EmptyRequestResponse {})
    }
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

    BigUint::from_str_radix(hex_string, 16 /* radix */).map_err(|e| {
        DeserializeError::custom(format!("error deserializing BigUint from hex string: {e}"))
    })
}

#[cfg(test)]
mod test {
    use super::EmptyRequestResponse;

    /// Tests empty request/response serialization, expected behavior is that it
    /// serializes to and from the string "null"
    #[test]
    fn test_serde_empty() {
        let req = EmptyRequestResponse {};
        let serialized_str = serde_json::to_string(&req).unwrap();
        assert_eq!(serialized_str, "null");

        // Test deserialization from empty json struct encoded as a string
        let _req: EmptyRequestResponse = serde_json::from_str("null").unwrap();
    }
}
