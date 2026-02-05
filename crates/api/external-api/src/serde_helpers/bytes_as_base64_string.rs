//! Serialize bytes as base64 strings

use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD as BASE64_ENGINE};
use serde::{Deserialize, Deserializer, Serializer};

/// Serialize a `Vec<u8>` as a base64 string
pub fn serialize<S>(val: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&BASE64_ENGINE.encode(val))
}

/// Deserialize a `Vec<u8>` from a base64 string
pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let base64_str = String::deserialize(deserializer)?;
    BASE64_ENGINE.decode(&base64_str).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod test {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestStruct {
        #[serde(with = "crate::serde_helpers::bytes_as_base64_string")]
        bytes: Vec<u8>,
    }

    #[test]
    fn test_round_trip_serialization() {
        let original = TestStruct { bytes: vec![0x01, 0x02, 0x03, 0xff] };
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: TestStruct = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_empty_bytes() {
        let original = TestStruct { bytes: vec![] };
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: TestStruct = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }
}
