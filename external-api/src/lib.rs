//! The API module defines messaging interfaces between p2p nodes
#![deny(missing_docs)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use num_bigint::BigUint;
use serde::{de::Error as DeserializeError, Deserialize, Deserializer, Serialize, Serializer};
use util::hex::{biguint_from_hex_string, biguint_to_hex_string};

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
pub fn serialize_biguint_to_hex_string<S>(val: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex = biguint_to_hex_string(val);
    serializer.serialize_str(&hex)
}

/// A helper to deserialize a BigUint from a hex string
pub fn deserialize_biguint_from_hex_string<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    let hex = String::deserialize(deserializer)?;
    biguint_from_hex_string(&hex).map_err(D::Error::custom)
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
