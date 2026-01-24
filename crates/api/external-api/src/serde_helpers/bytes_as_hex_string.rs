//! Serialize bytes as hex strings

use serde::{Deserialize, Deserializer, Serializer};
use util::hex::{bytes_from_hex_string, bytes_to_hex_string};

/// Serialize a `Vec<u8>` as a hex string
pub fn serialize<S>(val: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&bytes_to_hex_string(val))
}

/// Deserialize a `Vec<u8>` from a hex string
pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_str = String::deserialize(deserializer)?;
    bytes_from_hex_string(&hex_str).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod test {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestStruct {
        #[serde(with = "crate::serde_helpers::bytes_as_hex_string")]
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
