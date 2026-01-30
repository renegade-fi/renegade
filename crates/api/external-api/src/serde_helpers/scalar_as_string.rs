//! Serialize scalars as strings

use constants::Scalar;
use serde::{Deserialize, Deserializer, Serializer};

/// Serialize a `Scalar` as a string
pub fn serialize<S>(val: &Scalar, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&val.to_string())
}

/// Deserialize a `Scalar` from a string
pub fn deserialize<'de, D>(deserializer: D) -> Result<Scalar, D::Error>
where
    D: Deserializer<'de>,
{
    let scalar_str = String::deserialize(deserializer)?;
    Scalar::from_decimal_string(&scalar_str).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod test {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestStruct {
        #[serde(with = "crate::serde_helpers::scalar_as_string")]
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
