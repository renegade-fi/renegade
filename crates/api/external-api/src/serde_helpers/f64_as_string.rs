//! Serialize f64 as strings

use serde::{Deserialize, Deserializer, Serializer};

/// Serialize an `f64` as a string
pub fn serialize<S>(val: &f64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&val.to_string())
}

/// Deserialize an `f64` from a string
pub fn deserialize<'de, D>(deserializer: D) -> Result<f64, D::Error>
where
    D: Deserializer<'de>,
{
    let f64_str = String::deserialize(deserializer)?;
    f64_str.parse::<f64>().map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod test {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestStruct {
        #[serde(with = "crate::serde_helpers::f64_as_string")]
        value: f64,
    }

    #[test]
    fn test_round_trip_serialization() {
        let original = TestStruct { value: 123.456 };
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: TestStruct = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_zero() {
        let original = TestStruct { value: 0.0 };
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: TestStruct = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_negative() {
        let original = TestStruct { value: -42.5 };
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: TestStruct = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }
}
