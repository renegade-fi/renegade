//! Groups type definitions relevant to the handshake process

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use crypto::fields::DalekRistrettoField;
use serde::{
    de::{Error as DeserializeError, Visitor},
    ser::Error as SerializeError,
    Deserialize, Serialize,
};
use std::fmt::{Formatter, Result as FmtResult};

/// A wrapper around a hasher's output that both:
///     1. Abstracts the underlying field details
///     2. Allows us to implement serialization/deserialization traits
#[derive(Copy, Clone, Debug)]
pub struct HashOutput(pub DalekRistrettoField);

impl From<u64> for HashOutput {
    fn from(x: u64) -> Self {
        Self(DalekRistrettoField::from(x))
    }
}

impl Serialize for HashOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Use the Arkworks compression/serialization implementation
        let mut buf = Vec::new();
        self.0.serialize_compressed(&mut buf).map_err(|err| {
            SerializeError::custom(format!("error serializing HashOutput: {}", err))
        })?;

        serializer.serialize_bytes(&buf)
    }
}

impl<'de> Deserialize<'de> for HashOutput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(HashOutputVisitor)
    }
}

/// Serde visitor implementation for deserializing arkworks field elements
/// wrapped in the HashOutput abstraction
struct HashOutputVisitor;
impl<'de> Visitor<'de> for HashOutputVisitor {
    type Value = HashOutput;

    fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
        formatter.write_str("a HashOutput encoded as a byte array")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut bytes_vec = Vec::new();
        while let Some(value) = seq.next_element()? {
            bytes_vec.push(value);
        }

        let res =
            DalekRistrettoField::deserialize_compressed(bytes_vec.as_slice()).map_err(|err| {
                DeserializeError::custom(format!(
                    "deserializing byte array to HashOutput: {:?}",
                    err
                ))
            })?;

        Ok(HashOutput(res))
    }
}
