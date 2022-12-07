//! Groups the types used to represent the gossip network primitives

use ed25519_dalek::{PublicKey, SignatureError};
use libp2p::{Multiaddr, PeerId};
use libp2p_core::ParseError as PeerIdParseError;
use serde::{
    de::{Error as SerdeErr, Visitor},
    Deserialize, Serialize,
};
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    ops::Deref,
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::api::cluster_management::CLUSTER_MANAGEMENT_TOPIC_PREFIX;

/// Contains information about connected peers
#[derive(Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    /// The identifier used by libp2p for a peer
    peer_id: WrappedPeerId,
    /// The multiaddr of the peer
    addr: Multiaddr,
    /// Last time a successful hearbeat was received from this peer
    #[serde(skip)]
    last_heartbeat: AtomicU64,
    /// The ID of the cluster the peer belongs to
    cluster_id: ClusterId,
}

impl Eq for PeerInfo {}
impl PartialEq for PeerInfo {
    fn eq(&self, other: &Self) -> bool {
        self.peer_id == other.peer_id
            && self.addr == other.addr
            && self.last_heartbeat.load(Ordering::Relaxed)
                == other.last_heartbeat.load(Ordering::Relaxed)
            && self.cluster_id == other.cluster_id
    }
}

impl PeerInfo {
    /// Construct a new PeerInfo object
    pub fn new(peer_id: WrappedPeerId, cluster_id: ClusterId, addr: Multiaddr) -> Self {
        Self {
            addr,
            peer_id,
            cluster_id,
            last_heartbeat: AtomicU64::new(current_time_seconds()),
        }
    }

    /// Getters and Setters
    pub fn get_peer_id(&self) -> WrappedPeerId {
        self.peer_id
    }

    /// Get the address stored in the PeerInfo
    pub fn get_addr(&self) -> Multiaddr {
        self.addr.clone()
    }

    /// Get the ID of the cluster this peer belongs to
    pub fn get_cluster_id(&self) -> ClusterId {
        self.cluster_id.clone()
    }

    /// Records a successful heartbeat
    pub fn successful_heartbeat(&self) {
        self.last_heartbeat
            .store(current_time_seconds(), Ordering::Relaxed);
    }

    /// Get the last time a heartbeat was recorded for this peer
    pub fn get_last_heartbeat(&self) -> u64 {
        self.last_heartbeat.load(Ordering::Relaxed)
    }
}

/// Clones PeerInfo to reference the current time for the last heartbeat
impl Clone for PeerInfo {
    fn clone(&self) -> Self {
        Self {
            peer_id: self.peer_id,
            addr: self.addr.clone(),
            last_heartbeat: AtomicU64::new(self.last_heartbeat.load(Ordering::Relaxed)),
            cluster_id: self.cluster_id.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
/// Wraps PeerID so that we can implement various traits on the type
pub struct WrappedPeerId(pub PeerId);

impl WrappedPeerId {
    /// Create a random PeerID and wrap it
    pub fn random() -> Self {
        Self(PeerId::random())
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
/// A type alias for the cluster identifier
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterId(String);

impl ClusterId {
    /// Construct a clusterID, it's more readable and debuggable to compress the
    /// public key into a base64 encoded representation than to use the value directly
    pub fn new(cluster_pubkey: &PublicKey) -> Self {
        let encoded_key = base64::encode(cluster_pubkey.as_bytes());
        Self(encoded_key)
    }

    /// Get the cluster management pubsub topic name for the cluster idenified
    pub fn get_management_topic(&self) -> String {
        format!("{}-{}", CLUSTER_MANAGEMENT_TOPIC_PREFIX, self.0)
    }

    /// Get the public key represented by this cluster
    pub fn get_public_key(&self) -> Result<PublicKey, SignatureError> {
        let decoded_key = base64::decode(&self.0).map_err(|_| SignatureError::new())?;
        PublicKey::from_bytes(&decoded_key)
    }
}

/**
 * Helpers
 */

/// Returns a u64 representing the current unix timestamp in seconds
fn current_time_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("negative timestamp")
        .as_secs()
}

#[cfg(test)]
mod types_test {
    use std::sync::atomic::AtomicU64;

    use ed25519_dalek::Keypair as DalekKeypair;
    use libp2p::{identity::Keypair, Multiaddr, PeerId};
    use rand_core::OsRng;

    use super::{ClusterId, PeerInfo, WrappedPeerId};

    /// Tests that message serialization and deserialization works properly
    #[test]
    fn test_serialize_deserialize() {
        let mut rng = OsRng {};
        let random_keypair = DalekKeypair::generate(&mut rng);
        let libp2p_keypair = Keypair::generate_ed25519();

        let peer_id = WrappedPeerId(PeerId::from_public_key(&libp2p_keypair.public()));
        let cluster_id = ClusterId::new(&random_keypair.public);

        let peer_info = PeerInfo {
            peer_id,
            cluster_id,
            last_heartbeat: AtomicU64::new(0),
            addr: Multiaddr::empty(),
        };

        let serialized = serde_json::to_string(&peer_info).unwrap();
        let deserialized: PeerInfo = serde_json::from_str(&serialized).unwrap();

        assert_eq!(peer_info, deserialized)
    }
}
