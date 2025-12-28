//! WrappedPeerId type for wrapping libp2p's PeerId

use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    ops::Deref,
    str::FromStr,
};

use ed25519_dalek::SECRET_KEY_LENGTH;
use libp2p::PeerId;
use libp2p_identity::{
    ParseError as PeerIdParseError, ed25519::Keypair as LibP2PKeypair,
    ed25519::SecretKey as LibP2PSecretKey,
};
use serde::{
    Deserialize, Serialize,
    de::{Error as SerdeErr, Visitor},
};

/// Wraps PeerID so that we can implement various traits on the type
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct WrappedPeerId(pub PeerId);

impl WrappedPeerId {
    /// Create a random PeerID and wrap it
    pub fn random() -> Self {
        Self(PeerId::random())
    }

    /// Get the underlying peer ID
    pub fn inner(&self) -> PeerId {
        self.0
    }
}

impl Default for WrappedPeerId {
    fn default() -> Self {
        let skey = LibP2PSecretKey::try_from_bytes(&mut vec![0; SECRET_KEY_LENGTH]).unwrap();
        let keypair = LibP2PKeypair::from(skey);
        let peer_id = PeerId::from_public_key(&keypair.public().into());
        Self(peer_id)
    }
}

impl FromStr for WrappedPeerId {
    type Err = PeerIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(WrappedPeerId(PeerId::from_str(s)?))
    }
}

/// Deref so that the wrapped type can be referenced
impl Deref for WrappedPeerId {
    type Target = PeerId;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for WrappedPeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> FmtResult {
        self.0.fmt(f)
    }
}

/// Serialize PeerIDs
impl Serialize for WrappedPeerId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.to_bytes();
        serializer.serialize_bytes(&bytes)
    }
}

/// Deserialize PeerIDs
impl<'de> Deserialize<'de> for WrappedPeerId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(PeerIDVisitor)
    }
}

/// Visitor struct for help deserializing PeerIDs
struct PeerIDVisitor;
impl<'de> Visitor<'de> for PeerIDVisitor {
    type Value = WrappedPeerId;

    fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
        formatter.write_str("a libp2p::PeerID encoded as a byte array")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: SerdeErr,
    {
        PeerId::from_bytes(v)
            .map(WrappedPeerId)
            .map_err(|e| SerdeErr::custom(format!("deserializing byte array to PeerID: {e:?}")))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut bytes_vec = Vec::new();
        while let Some(value) = seq.next_element()? {
            bytes_vec.push(value);
        }

        if let Ok(peer_id) = PeerId::from_bytes(&bytes_vec[..]) {
            return Ok(WrappedPeerId(peer_id));
        }

        Err(SerdeErr::custom("deserializing byte array to PeerID"))
    }
}

// -----------------------
// | rkyv Implementation |
// -----------------------

#[cfg(feature = "rkyv")]
mod rkyv_impl {
    //! rkyv serialization for WrappedPeerId
    //!
    //! PeerId is serialized as its byte representation (variable length).
    //! We store it as a Vec<u8> and convert on (de)serialization.

    use libp2p::PeerId;
    use rkyv::{
        Archive, Deserialize as RkyvDeserialize, Place, Serialize as RkyvSerialize,
        rancor::{Fallible, Source},
        vec::{ArchivedVec, VecResolver},
    };

    use super::WrappedPeerId;

    /// The archived form of WrappedPeerId - stored as bytes
    pub type ArchivedWrappedPeerId = ArchivedVec<u8>;
    impl Archive for WrappedPeerId {
        type Archived = ArchivedWrappedPeerId;
        type Resolver = VecResolver;

        fn resolve(&self, resolver: Self::Resolver, out: Place<Self::Archived>) {
            let bytes = self.to_bytes();
            ArchivedVec::resolve_from_slice(&bytes, resolver, out);
        }
    }

    impl<S: Fallible + rkyv::ser::Allocator + rkyv::ser::Writer + ?Sized> RkyvSerialize<S>
        for WrappedPeerId
    {
        fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
            let bytes = self.to_bytes();
            ArchivedVec::serialize_from_slice(&bytes, serializer)
        }
    }

    impl<D: Fallible + ?Sized> RkyvDeserialize<WrappedPeerId, D> for ArchivedWrappedPeerId
    where
        D::Error: Source,
    {
        fn deserialize(&self, _deserializer: &mut D) -> Result<WrappedPeerId, D::Error> {
            let bytes: &[u8] = self.as_slice();
            let peer_id = PeerId::from_bytes(bytes).map_err(D::Error::new)?;
            Ok(WrappedPeerId(peer_id))
        }
    }

    impl PartialEq<WrappedPeerId> for ArchivedWrappedPeerId {
        fn eq(&self, other: &WrappedPeerId) -> bool {
            self.as_slice() == other.to_bytes().as_slice()
        }
    }

    impl PartialEq<ArchivedWrappedPeerId> for WrappedPeerId {
        fn eq(&self, other: &ArchivedWrappedPeerId) -> bool {
            self.to_bytes().as_slice() == other.as_slice()
        }
    }
}

#[cfg(feature = "rkyv")]
pub use rkyv_impl::ArchivedWrappedPeerId;
