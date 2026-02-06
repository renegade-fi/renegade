//! Serialize embedded scalar fields as decimal strings

use constants::EmbeddedScalarField;
use serde::{Deserialize, Deserializer, Serializer};
use util::hex::{embedded_scalar_from_decimal_string, embedded_scalar_to_decimal_string};

/// Serialize an `EmbeddedScalarField` as a decimal string
pub fn serialize<S>(val: &EmbeddedScalarField, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let decimal = embedded_scalar_to_decimal_string(val);
    serializer.serialize_str(&decimal)
}

/// Deserialize an `EmbeddedScalarField` from a decimal string
pub fn deserialize<'de, D>(deserializer: D) -> Result<EmbeddedScalarField, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    embedded_scalar_from_decimal_string(&s).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod test {
    use constants::EmbeddedScalarField;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestStruct {
        #[serde(with = "crate::serde_helpers::embedded_scalar_as_string")]
        scalar: EmbeddedScalarField,
    }

    #[test]
    fn test_round_trip_serialization() {
        let original = TestStruct { scalar: EmbeddedScalarField::default() };
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: TestStruct = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }
}
