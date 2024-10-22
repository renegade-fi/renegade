//! The API module defines messaging interfaces between p2p nodes
#![deny(missing_docs)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use std::fmt;

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use num_bigint::BigUint;
use serde::{
    de::{self, Error as DeserializeError, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use util::hex::{biguint_from_hex_string, biguint_to_hex_addr};

#[cfg(feature = "auth")]
pub mod auth;
pub mod bus_message;
pub mod http;
pub mod types;
pub mod websocket;

/// Header name for the HTTP auth signature; lower cased
pub const RENEGADE_AUTH_HEADER_NAME: &str = "x-renegade-auth";
/// Header name for the expiration timestamp of a signature; lower cased
pub const RENEGADE_SIG_EXPIRATION_HEADER_NAME: &str = "x-renegade-auth-expiration";

/// Header name for the HTTP auth HMAC
pub const RENEGADE_AUTH_HMAC_HEADER_NAME: &str = "x-renegade-auth-symmetric";

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

/// A helper to serialize a BigUint to a hex address
pub fn serialize_biguint_to_hex_addr<S>(val: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex = biguint_to_hex_addr(val);
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

/// BytesOrBase64Visitor is a custom deserializer for the statement_sig field
/// that allows either a json byte array or a base64 encoded string to be used
struct BytesOrBase64Visitor;
impl<'de> Visitor<'de> for BytesOrBase64Visitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a byte array or a base64 encoded string")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(v.to_vec())
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut bytes = Vec::new();
        while let Some(byte) = seq.next_element()? {
            bytes.push(byte);
        }
        Ok(bytes)
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        STANDARD_NO_PAD.decode(v).map_err(de::Error::custom)
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_str(&v)
    }
}

/// Deserializes a byte array, base64 encoded string, or JSON byte array
fn deserialize_bytes_or_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(BytesOrBase64Visitor)
}

/// A visitor for deserializing a `BigUint` from either a limb encoding or a
/// json number type
struct BigUintVisitor;
impl<'de> Visitor<'de> for BigUintVisitor {
    type Value = BigUint;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a limb encoding or a json string representation of a number")
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: DeserializeError,
    {
        Ok(BigUint::from(v))
    }

    fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
    where
        E: DeserializeError,
    {
        Ok(BigUint::from(v))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        value.parse().map_err(E::custom)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut limbs = Vec::new();
        while let Some(limb) = seq.next_element()? {
            limbs.push(limb);
        }
        Ok(BigUint::new(limbs))
    }
}

/// Deserializes a `BigUint` from either a limb encoding or a json number type
fn deserialize_limbs_or_number<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(BigUintVisitor)
}

#[cfg(test)]
mod test {
    use rand::{thread_rng, RngCore};
    use serde::{Deserialize, Serialize};
    use serde_json::json;

    use super::*;

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

    /// A test structure for deserializing a byte array from multiple encodings
    #[derive(Debug, Serialize, Deserialize)]
    struct BytesOrBase64Test {
        /// A byte array
        #[serde(deserialize_with = "deserialize_bytes_or_base64")]
        bytes: Vec<u8>,
    }

    /// Tests deserializing a byte array as a base64 encoded string
    #[test]
    #[allow(non_snake_case)]
    fn test_serde_bytes_or_base64__from_base64() {
        let mut rng = thread_rng();
        let mut bytes = vec![0u8; 10];
        rng.fill_bytes(&mut bytes);
        let base64_str = STANDARD_NO_PAD.encode(&bytes);

        // Deserialize from a JSON string
        let json = json!({
            "bytes": base64_str
        })
        .to_string();

        let test_struct: BytesOrBase64Test = serde_json::from_str(&json).unwrap();
        assert_eq!(test_struct.bytes, bytes);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_serde_bytes_or_base64__from_bytes() {
        let mut rng = thread_rng();
        let mut bytes = vec![0u8; 10];
        rng.fill_bytes(&mut bytes);

        // Deserialize from a JSON string
        let json = json!({
            "bytes": bytes
        })
        .to_string();

        let test_struct: BytesOrBase64Test = serde_json::from_str(&json).unwrap();
        assert_eq!(test_struct.bytes, bytes);
    }

    /// A test structure for deserializing a `BigUint` from either a limb
    /// encoding or a json number type
    #[derive(Debug, Serialize, Deserialize)]
    struct BigUintTest {
        #[serde(deserialize_with = "deserialize_limbs_or_number")]
        value: BigUint,
    }

    /// Tests deserializing a `BigUint` from a number
    #[test]
    fn test_deserialize_biguint_from_number() {
        let mut rng = thread_rng();
        let val = rng.next_u64();

        let json = json!({
            "value": val
        })
        .to_string();

        let test_struct: BigUintTest = serde_json::from_str(&json).unwrap();
        let expected = BigUint::from(val);
        assert_eq!(test_struct.value, expected);
    }

    /// Tests deserializing a `BigUint` from a string
    #[test]
    fn test_deserialize_biguint_from_string() {
        let json = r#"{"value": "115792089237316195423570985008687907853269984665640564039457584007913129639936"}"#; // 2^256
        let test_struct: BigUintTest = serde_json::from_str(json).unwrap();
        let expected = BigUint::from(1u64) << 256;

        assert_eq!(test_struct.value, expected);
    }

    /// Tests deserializing a `BigUint` from a limb encoding
    #[test]
    fn test_deserialize_biguint_from_limbs() {
        const NUM_LIMBS: usize = 10;
        let mut rng = thread_rng();
        let mut u32_limbs = vec![0u32; NUM_LIMBS];
        for limb in u32_limbs.iter_mut() {
            *limb = rng.next_u32();
        }

        let json = json!({
            "value": u32_limbs
        })
        .to_string();

        let test_struct: BigUintTest = serde_json::from_str(&json).unwrap();
        let expected = BigUint::new(u32_limbs.to_vec());
        assert_eq!(test_struct.value, expected);
    }
}
