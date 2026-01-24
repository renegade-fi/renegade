//! Serialize amounts as strings

use circuit_types::Amount;
use serde::{Deserialize, Deserializer, Serializer};

/// Serialize an `Amount` as a string
pub fn serialize<S>(val: &Amount, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&val.to_string())
}

/// Deserialize an `Amount` from a string
pub fn deserialize<'de, D>(deserializer: D) -> Result<Amount, D::Error>
where
    D: Deserializer<'de>,
{
    let amount_str = String::deserialize(deserializer)?;
    amount_str.parse::<Amount>().map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod test {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestStruct {
        #[serde(with = "crate::serde_helpers::amount_as_string")]
        amount: Amount,
    }

    #[test]
    fn test_round_trip_serialization() {
        let original = TestStruct { amount: 100 };
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: TestStruct = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }
}
