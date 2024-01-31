//! Request response types for raft communication

use protobuf::Message;
use raft::prelude::Message as RawRaftMessage;
use serde::{ser::SerializeSeq, Deserialize, Deserializer, Serialize, Serializer};

// ----------------
// | Message Type |
// ----------------

/// A raft message wrapper that allows us to implement serde serialization and
/// deserialization on the type
#[derive(Clone, Debug)]
pub struct RaftMessage(pub RawRaftMessage);

impl RaftMessage {
    /// Constructor
    pub fn new(message: RawRaftMessage) -> Self {
        Self(message)
    }

    /// Get the inner message compatible with the `raft` crate
    pub fn inner(&self) -> &RawRaftMessage {
        &self.0
    }

    /// Consume the wrapper and return the inner value
    pub fn into_inner(self) -> RawRaftMessage {
        self.0
    }
}

impl Serialize for RaftMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.0.write_to_bytes().map_err(serde::ser::Error::custom)?;
        let mut seq = serializer.serialize_seq(Some(bytes.len()))?;
        for byte in bytes {
            seq.serialize_element(&byte)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for RaftMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        let message = RawRaftMessage::parse_from_bytes(&bytes).map_err(serde::de::Error::custom)?;
        Ok(Self(message))
    }
}
