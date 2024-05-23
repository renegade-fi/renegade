//! Defines types related to the gossip network structure

//! Groups the types used to represent the gossip network primitives

use derivative::Derivative;
use ed25519_dalek::{
    Digest, Keypair, PublicKey, Sha512, Signature, SignatureError, SECRET_KEY_LENGTH,
};
use libp2p::{Multiaddr, PeerId};
use libp2p_identity::{
    ed25519::Keypair as LibP2PKeypair, ed25519::SecretKey as LibP2PSecretKey,
    ParseError as PeerIdParseError,
};
use serde::{
    de::{Error as SerdeErr, Visitor},
    Deserialize, Serialize,
};
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    ops::Deref,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};
use util::{get_current_time_millis, networking::is_dialable_multiaddr};

/// The topic prefix for the cluster management pubsub topic
///
/// The actual topic name will have the cluster ID postfixed; i.e.
///     cluster-management-{cluster_id}
pub const CLUSTER_MANAGEMENT_TOPIC_PREFIX: &str = "cluster-management";

/// Contains information about connected peers
#[derive(Clone, Debug, Serialize, Deserialize, Derivative)]
#[derivative(PartialEq, Eq)]
pub struct PeerInfo {
    /// The identifier used by libp2p for a peer
    pub peer_id: WrappedPeerId,
    /// The multiaddr of the peer
    pub addr: Multiaddr,
    /// Last time a successful heartbeat was received from this peer
    pub last_heartbeat: u64,
    /// The ID of the cluster the peer belongs to
    pub cluster_id: ClusterId,
    /// The signature of the peer's ID with their cluster private key, used to
    /// prove that the peer is a valid cluster member
    #[derivative(PartialEq = "ignore")]
    pub cluster_auth_signature: Vec<u8>,
}

impl Default for PeerInfo {
    fn default() -> Self {
        Self {
            peer_id: WrappedPeerId(PeerId::random()),
            addr: Multiaddr::empty(),
            last_heartbeat: 0,
            cluster_id: ClusterId("0".to_string()),
            cluster_auth_signature: vec![],
        }
    }
}

impl PeerInfo {
    /// Construct a new PeerInfo object
    pub fn new(
        peer_id: WrappedPeerId,
        cluster_id: ClusterId,
        addr: Multiaddr,
        cluster_auth_signature: Vec<u8>,
    ) -> Self {
        Self {
            addr,
            peer_id,
            cluster_id,
            cluster_auth_signature,
            last_heartbeat: current_time_seconds(),
        }
    }

    /// Construct a new PeerInfo object using the cluster private key
    pub fn new_with_cluster_secret_key(
        peer_id: WrappedPeerId,
        cluster_id: ClusterId,
        addr: Multiaddr,
        cluster_keypair: &Keypair,
    ) -> Self {
        // Generate an auth signature for the cluster
        let mut hash_digest = Sha512::new();
        hash_digest.update(&serde_json::to_vec(&peer_id).unwrap());
        let sig = cluster_keypair.sign_prehashed(hash_digest, None /* context */).unwrap();

        Self::new(peer_id, cluster_id, addr, sig.to_bytes().to_vec())
    }

    /// Verify that the signature on the peer's info is correct
    pub fn verify_cluster_auth_sig(&self) -> Result<(), SignatureError> {
        let sig = Signature::from_bytes(&self.cluster_auth_signature)
            .map_err(|_| SignatureError::new())?;
        let pubkey = self.cluster_id.get_public_key().map_err(|_| SignatureError::new())?;

        // Hash the peer ID and verify the signature
        let mut hash_digest = Sha512::new();
        hash_digest.update(&serde_json::to_vec(&self.peer_id).unwrap());
        pubkey.verify_prehashed(hash_digest, None, &sig)
    }

    /// Getters and Setters
    pub fn get_peer_id(&self) -> WrappedPeerId {
        self.peer_id
    }

    /// Get the address stored in the PeerInfo
    pub fn get_addr(&self) -> Multiaddr {
        self.addr.clone()
    }

    /// Returns whether or not the peer's address is dialable
    pub fn is_dialable(&self, allow_local: bool) -> bool {
        is_dialable_multiaddr(&self.addr, allow_local)
    }

    /// Get the ID of the cluster this peer belongs to
    pub fn get_cluster_id(&self) -> ClusterId {
        self.cluster_id.clone()
    }

    /// Records a successful heartbeat
    pub fn successful_heartbeat(&mut self) {
        self.last_heartbeat = get_current_time_millis();
    }

    /// Get the last time a heartbeat was recorded for this peer
    pub fn get_last_heartbeat(&self) -> u64 {
        self.last_heartbeat
    }
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
/// Wraps PeerID so that we can implement various traits on the type
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
/// A type alias for the cluster identifier
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterId(String);
impl ClusterId {
    /// Construct a clusterID, it's more readable and debuggable to compress the
    /// public key into a base64 encoded representation than to use the value
    /// directly
    pub fn new(cluster_pubkey: &PublicKey) -> Self {
        let encoded_key = base64::encode(cluster_pubkey.as_bytes());
        Self(encoded_key)
    }

    /// Get the cluster management pubsub topic name for the cluster identified
    pub fn get_management_topic(&self) -> String {
        format!("{}-{}", CLUSTER_MANAGEMENT_TOPIC_PREFIX, self.0)
    }

    /// Get the public key represented by this cluster
    pub fn get_public_key(&self) -> Result<PublicKey, SignatureError> {
        let decoded_key = base64::decode(&self.0).map_err(|_| SignatureError::new())?;
        PublicKey::from_bytes(&decoded_key)
    }
}

impl Display for ClusterId {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.0)
    }
}

impl FromStr for ClusterId {
    // Conversion does not error
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

// -----------
// | Helpers |
// -----------

/// Returns a u64 representing the current unix timestamp in seconds
fn current_time_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("negative timestamp").as_secs()
}

#[cfg(feature = "mocks")]
pub mod mocks {
    //! Mocks for peer info types
    use std::{
        net::{IpAddr, Ipv4Addr},
        str::FromStr,
    };

    use libp2p::Multiaddr;

    use super::{ClusterId, PeerInfo, WrappedPeerId};

    /// Build a mock peer's info
    pub fn mock_peer() -> PeerInfo {
        // Build an RPC message to add a peer
        let cluster_id = ClusterId::from_str("1234").unwrap();
        let peer_id = WrappedPeerId::random();
        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let addr = Multiaddr::from(addr);

        PeerInfo::new(peer_id, cluster_id, addr.clone(), vec![] /* signature */)
    }
}

#[cfg(test)]
mod types_test {

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
            cluster_auth_signature: Vec::new(),
            last_heartbeat: 0,
            addr: Multiaddr::empty(),
        };

        let serialized = serde_json::to_string(&peer_info).unwrap();
        let deserialized: PeerInfo = serde_json::from_str(&serialized).unwrap();

        assert_eq!(peer_info, deserialized)
    }
}
