//! Serialize U256 as decimal strings

use alloy::primitives::U256;
use serde::{Deserialize, Deserializer, Serializer};

/// Serialize a `U256` as a decimal string
pub fn serialize<S>(val: &U256, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&val.to_string())
}

/// Deserialize a `U256` from a decimal string
pub fn deserialize<'de, D>(deserializer: D) -> Result<U256, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    s.parse::<U256>().map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod test {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestStruct {
        #[serde(with = "crate::serde_helpers::u256_as_string")]
        value: U256,
    }

    #[test]
    fn test_round_trip_serialization() {
        let original = TestStruct { value: U256::from(12345) };
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: TestStruct = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }
}
