//! The API module defines messaging interfaces between p2p nodes
#![deny(missing_docs)]
#![allow(incomplete_features)]

use serde::{Deserialize, Serialize};

#[cfg(feature = "auth")]
pub mod auth;
pub mod http;
pub mod types;
#[cfg(feature = "websocket")]
pub mod websocket;

/// Header name for the HTTP auth signature; lower cased
pub const RENEGADE_AUTH_HEADER_NAME: &str = "x-renegade-auth";
/// Header name for the expiration timestamp of a signature; lower cased
pub const RENEGADE_SIG_EXPIRATION_HEADER_NAME: &str = "x-renegade-auth-expiration";

// -------------------------
// | Serialization Helpers |
// -------------------------

/// An empty request/response type
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmptyRequestResponse {}

/// Serialize an empty request/response
impl Serialize for EmptyRequestResponse {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_none()
    }
}

/// Deserialize an empty request/response
impl<'de> Deserialize<'de> for EmptyRequestResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_unit(EmptyRequestResponseVisitor)
    }
}

/// Visitor for deserializing an empty request/response
struct EmptyRequestResponseVisitor;
impl serde::de::Visitor<'_> for EmptyRequestResponseVisitor {
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

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
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
}
