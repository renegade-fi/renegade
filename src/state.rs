use libp2p::PeerId;
use serde::{Serialize, Deserialize, de::{Visitor, Error as SerdeErr}};
use std::{sync::{Arc, RwLock}, ops::Deref};


/**
 * This file groups type definitions and helpers around global state that 
 * is passed around throughout the code
 */

/**
 * Constants and Types
 */

// The ideal of peers that manage a given wallet in tandum
const TARGET_WALLET_REPLICAS: usize = 5;

// A type alias for the thread-safe relayer state
pub type GlobalRelayerState = Arc<RwLock<RelayerState>>;

/**
 * An implementation of a wrapper type that allows us to implement traits
 * on top of the existing libp2p PeerID type
 */

#[derive(Debug, PartialEq)]
// Wraps PeerID so that we can implement various traits on the type
struct WrappedPeerID(PeerId);

// Deref so that the wrapped type can be referenced
impl Deref for WrappedPeerID {
    type Target = PeerId;

    fn deref(&self) -> &Self::Target {
        &self.0        
    }
}

// Serialize PeerIDs
impl Serialize for WrappedPeerID {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer 
    {
        let bytes = self.to_bytes();
        serializer.serialize_bytes(&bytes)
    }
}

// Deserialize PeerIDs
impl<'de> Deserialize<'de> for WrappedPeerID {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de> 
    {
        deserializer.deserialize_seq(PeerIDVisitor)
    }
}

// Visitor struct for help deserializing PeerIDs
struct PeerIDVisitor;
impl<'de> Visitor<'de> for PeerIDVisitor {
    type Value = WrappedPeerID;

    // Debug message
    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
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
            return Ok(WrappedPeerID(peer_id))
        }

        Err(SerdeErr::custom("deserializing byte array to PeerID"))
    }
}

/**
 * State objects
 * Use #[serde(skip)] to maintain private state
 */

#[derive(Debug, Serialize, Deserialize)]
// The top level object in the global state tree
pub struct RelayerState {
    // The list of wallets that this peer manages
    managed_wallets: Vec<Wallet>,

    // Currently here for serde testing, will be replaced
    #[serde(skip)]
    private_key: String
}

#[derive(Debug, Serialize, Deserialize)]
// Represents a wallet managed by the local relayer
pub struct Wallet {
    // Wallet metadata; replicas, trusted peers, etc
    metadata: WalletMetadata,
}

#[derive(Debug, Serialize, Deserialize)]
// Metadata relevant to the wallet's network state
pub struct WalletMetadata {
    replicas: Vec<WrappedPeerID>,
}

impl RelayerState {
    pub fn initialize_global_state() -> GlobalRelayerState {
        Arc::new(
            RwLock::new(
                Self { managed_wallets: Vec::new(), private_key: "".to_string() }
            )
        )
    }
}

/**
 * Tests
 */
#[cfg(test)]
mod tests {
    use libp2p::{identity::Keypair, PeerId};
    use serde_json;

    use super::{RelayerState, WrappedPeerID};

    #[test]
    // Build a wrapped peer id, serialize it, then deserialize
    fn test_wrapped_peerid_serde() {
        let local_key = Keypair::generate_ed25519();
        let peer_id = WrappedPeerID(
            PeerId::from_public_key(&local_key.public())
        );

        let serialized = serde_json::to_string(&peer_id).unwrap();
        println!("\nSerialized: {:?}\n", serialized);
        let deserialized: WrappedPeerID = serde_json::from_str(&serialized.to_string()).unwrap();

        assert_eq!(deserialized, peer_id);
    }

    #[test]
    // Tests that serialization skips private fields (e.g. private key)
    // This is important as the protocol implementation automatically serializes and
    // deserializes the state structs, so we would like this behaivor to be automatic
    fn test_skip_private_fields() {
        let relayer_state = RelayerState { managed_wallets: Vec::new(), private_key: "secret".to_string() };
        let serialized = serde_json::to_string(&relayer_state).unwrap();
        let deserialized: RelayerState = serde_json::from_str(&serialized).unwrap();

        assert_eq!("", deserialized.private_key);
    }
}