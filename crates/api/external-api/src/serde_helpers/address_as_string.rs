//! Serialize addresses as strings

use alloy::primitives::Address;
use serde::{Deserialize, Deserializer, Serializer};
use util::hex::{address_from_hex_string, address_to_hex_string};

/// Serialize an `Address` as a string
pub fn serialize<S>(val: &Address, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&address_to_hex_string(val))
}

/// Deserialize an `Address` from a string
pub fn deserialize<'de, D>(deserializer: D) -> Result<Address, D::Error>
where
    D: Deserializer<'de>,
{
    let address_str = String::deserialize(deserializer)?;
    address_from_hex_string(&address_str).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod test {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestStruct {
        #[serde(with = "crate::serde_helpers::address_as_string")]
        address: Address,
    }

    #[test]
    fn test_round_trip_serialization() {
        let original = TestStruct { address: Address::ZERO };
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: TestStruct = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }
}
