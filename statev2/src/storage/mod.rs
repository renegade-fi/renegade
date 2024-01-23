//! Defines the access patterns and interface to the durable storage layer
//! concretely implemented as an `mdbx` instance

use std::borrow::Cow;

use protobuf::Message;
use serde::{ser::Error as SerializeError, Serialize};

pub mod cursor;
pub mod db;
pub mod error;
pub mod traits;
pub mod tx;

/// A type alias used for reading from the database
type CowBuffer<'a> = Cow<'a, [u8]>;

/// A wrapper struct that allows us to implement serde traits on a protobuf
/// `Message` which lets us store protobuf messages in the database
#[derive(Clone, Debug, PartialEq)]
pub struct ProtoStorageWrapper<T: Message>(pub T);
impl<T: Message> ProtoStorageWrapper<T> {
    /// Unwraps the inner protobuf message
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: Message> Default for ProtoStorageWrapper<T> {
    fn default() -> Self {
        Self(T::new())
    }
}

impl<T: Message> Serialize for ProtoStorageWrapper<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.0.write_to_bytes().map_err(SerializeError::custom)?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de, T: Message> serde::Deserialize<'de> for ProtoStorageWrapper<T> {
    fn deserialize<D>(deserializer: D) -> Result<ProtoStorageWrapper<T>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <&[u8]>::deserialize(deserializer)?;

        let mut msg = T::new();
        msg.merge_from_bytes(bytes).map_err(serde::de::Error::custom)?;

        Ok(ProtoStorageWrapper(msg))
    }
}
