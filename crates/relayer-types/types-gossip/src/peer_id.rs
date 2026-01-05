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
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug), compare(PartialEq)))]
pub struct WrappedPeerId(#[cfg_attr(feature = "rkyv", rkyv(with = PeerIdDef))] pub PeerId);

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
    //! Uses a remote type shim pattern for PeerId serialization.

    use libp2p::PeerId;
    use rkyv::{Archive, Deserialize, Serialize};

    // -------------
    // | PeerIdDef |
    // -------------

    /// Remote type shim for `libp2p::PeerId`
    #[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
    #[rkyv(derive(Debug), compare(PartialEq))]
    #[rkyv(remote = libp2p::PeerId)]
    #[rkyv(archived = ArchivedPeerId)]
    pub struct PeerIdDef {
        /// The underlying multihash.
        #[rkyv(getter = AsRef::as_ref, with = MultihashDef)]
        pub multihash: libp2p::multihash::MultihashGeneric<64>,
    }

    impl From<PeerIdDef> for PeerId {
        fn from(value: PeerIdDef) -> Self {
            PeerId::try_from(value.multihash).expect("Invalid PeerId multihash")
        }
    }

    impl PartialEq<libp2p::PeerId> for ArchivedPeerId {
        fn eq(&self, other: &libp2p::PeerId) -> bool {
            self.multihash == *other.as_ref()
        }
    }

    /// A multihash shim for `multihash::Multihash`
    #[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
    #[rkyv(derive(Debug), compare(PartialEq))]
    #[rkyv(remote = libp2p::multihash::MultihashGeneric<64>)]
    #[rkyv(archived = ArchivedMultihash)]
    pub struct MultihashDef {
        /// The code of the Multihash.
        #[rkyv(getter = libp2p::multihash::Multihash::code)]
        pub code: u64,
        /// The digest.
        #[rkyv(getter = get_digest)]
        pub digest: Vec<u8>,
    }

    /// Get a multi-hash digest
    fn get_digest(mh: &libp2p::multihash::MultihashGeneric<64>) -> Vec<u8> {
        mh.digest().to_vec()
    }

    impl From<MultihashDef> for libp2p::multihash::MultihashGeneric<64> {
        fn from(value: MultihashDef) -> Self {
            libp2p::multihash::MultihashGeneric::<64>::wrap(value.code, &value.digest).unwrap()
        }
    }

    impl PartialEq<libp2p::multihash::MultihashGeneric<64>> for ArchivedMultihash {
        fn eq(&self, other: &libp2p::multihash::MultihashGeneric<64>) -> bool {
            self.code == other.code() && self.digest == other.digest().to_vec()
        }
    }
}

#[cfg(feature = "rkyv")]
pub use rkyv_impl::PeerIdDef;
