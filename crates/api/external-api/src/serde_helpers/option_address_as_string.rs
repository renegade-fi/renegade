//! Serialize optional addresses as strings

use alloy::primitives::Address;
use serde::{Deserialize, Deserializer, Serializer};
use util::hex::{address_from_hex_string, address_to_hex_string};

/// Serialize an `Option<Address>` as a string
pub fn serialize<S>(val: &Option<Address>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match val {
        Some(addr) => serializer.serialize_str(&address_to_hex_string(addr)),
        None => serializer.serialize_none(),
    }
}

/// Deserialize an `Option<Address>` from a string
pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Address>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        Some(address_str) => {
            let addr = address_from_hex_string(&address_str).map_err(serde::de::Error::custom)?;
            Ok(Some(addr))
        },
        None => Ok(None),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestStruct {
        #[serde(with = "crate::serde_helpers::option_address_as_string")]
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        address: Option<Address>,
    }

    #[test]
    fn test_round_trip_some() {
        let original = TestStruct { address: Some(Address::ZERO) };
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: TestStruct = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_round_trip_none() {
        let original = TestStruct { address: None };
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: TestStruct = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_missing_field() {
        let json = "{}";
        let deserialized: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(deserialized.address, None);
    }

    #[test]
    fn test_explicit_null() {
        let json = r#"{"address": null}"#;
        let deserialized: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(deserialized.address, None);
    }
}
