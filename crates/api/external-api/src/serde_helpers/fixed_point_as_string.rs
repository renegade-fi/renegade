//! Serialize fixed points as strings

use circuit_types::fixed_point::FixedPoint;
use constants::Scalar;
use serde::{Deserialize, Deserializer, Serializer};

/// Serialize a `FixedPoint` as a string
pub fn serialize<S>(val: &FixedPoint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let repr_string = val.repr.to_string();
    serializer.serialize_str(&repr_string)
}

/// Deserialize a `FixedPoint` from a string
pub fn deserialize<'de, D>(deserializer: D) -> Result<FixedPoint, D::Error>
where
    D: Deserializer<'de>,
{
    let repr_string = String::deserialize(deserializer)?;
    let repr = Scalar::from_decimal_string(&repr_string).map_err(|e| {
        serde::de::Error::custom(format!("error deserializing FixedPoint from string: {e}"))
    })?;

    Ok(FixedPoint { repr })
}

#[cfg(test)]
mod test {
    use serde::{Deserialize, Serialize};

    use crate::serde_helpers;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestStruct {
        #[serde(with = "serde_helpers::fixed_point_as_string")]
        price: circuit_types::fixed_point::FixedPoint,
    }

    #[test]
    fn test_round_trip_serialization() {
        use circuit_types::fixed_point::FixedPoint;
        let original = TestStruct { price: FixedPoint::zero() };
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: TestStruct = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }
}
