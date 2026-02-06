//! Serialize an `HmacKey` as a base64 string

use serde::{Deserialize, Deserializer, Serializer};
use types_core::HmacKey;

/// Serialize an `HmacKey` as a base64 string
pub fn serialize<S>(val: &HmacKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&val.to_base64_string())
}

/// Deserialize an `HmacKey` from a base64 string
pub fn deserialize<'de, D>(deserializer: D) -> Result<HmacKey, D::Error>
where
    D: Deserializer<'de>,
{
    let base64_str = String::deserialize(deserializer)?;
    HmacKey::from_base64_string(&base64_str).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod test {
    use serde::{Deserialize, Serialize};
    use types_core::HmacKey;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestStruct {
        #[serde(with = "crate::serde_helpers::hmac_key_as_base64_string")]
        key: HmacKey,
    }

    #[test]
    fn test_round_trip_serialization() {
        let original = TestStruct { key: HmacKey::random() };
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: TestStruct = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }
}
