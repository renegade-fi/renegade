//! Serialize scalars as hex strings

use constants::Scalar;
use serde::{Deserialize, Deserializer, Serializer};
use util::hex::{scalar_from_hex_string, scalar_to_hex_string};

/// Serialize a `Scalar` as a hex string
pub fn serialize<S>(val: &Scalar, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&scalar_to_hex_string(val))
}

/// Deserialize a `Scalar` from a hex string
pub fn deserialize<'de, D>(deserializer: D) -> Result<Scalar, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_str = String::deserialize(deserializer)?;
    scalar_from_hex_string(&hex_str).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod test {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestStruct {
        #[serde(with = "crate::serde_helpers::scalar_as_hex_string")]
        scalar: Scalar,
    }

    #[test]
    fn test_round_trip_serialization() {
        let original = TestStruct { scalar: Scalar::zero() };
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: TestStruct = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }
}
