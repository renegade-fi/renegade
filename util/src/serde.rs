//! Serialization and deserialization utilities

use serde::Deserialize;

/// Deserialize a string into lowercase
pub fn deserialize_str_lower<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(|s| s.to_lowercase())
}

/// Serialize a string as lowercase
pub fn serialize_str_lower<S>(value: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&value.to_lowercase())
}
