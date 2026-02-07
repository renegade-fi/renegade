//! Serialize Schnorr public keys as hex strings
//!
//! Uses the Baby JubJub point hex serialization format, since a Schnorr
//! public key is simply a point on the Baby JubJub curve.

use circuit_types::schnorr::SchnorrPublicKey;
use serde::{Deserialize, Deserializer, Serializer};
use util::hex::{jubjub_from_hex_string, jubjub_to_hex_string};

/// Serialize a `SchnorrPublicKey` as a hex string
pub fn serialize<S>(val: &SchnorrPublicKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex = jubjub_to_hex_string(&val.point);
    serializer.serialize_str(&hex)
}

/// Deserialize a `SchnorrPublicKey` from a hex string
pub fn deserialize<'de, D>(deserializer: D) -> Result<SchnorrPublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_str = String::deserialize(deserializer)?;
    let point = jubjub_from_hex_string(&hex_str).map_err(serde::de::Error::custom)?;
    Ok(SchnorrPublicKey { point })
}

#[cfg(test)]
mod test {
    use circuit_types::schnorr::{SchnorrPrivateKey, SchnorrPublicKey};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestStruct {
        #[serde(with = "crate::serde_helpers::schnorr_public_key_as_string")]
        key: SchnorrPublicKey,
    }

    #[test]
    fn test_round_trip_serialization() {
        let pk = SchnorrPrivateKey::random().public_key();
        let original = TestStruct { key: pk };
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: TestStruct = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }
}
