//! Peer information types for gossip network

use derivative::Derivative;
use ed25519_dalek::{Digest, Keypair, Sha512, Signature, SignatureError};
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use util::{get_current_time_millis, networking::is_dialable_multiaddr};

use crate::{ClusterId, WrappedPeerId};

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
            cluster_id: ClusterId::from_str_infallible("0"),
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
            last_heartbeat: get_current_time_millis(),
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
        hash_digest.update(serde_json::to_vec(&peer_id).unwrap());
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
        hash_digest.update(serde_json::to_vec(&self.peer_id).unwrap());
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

// -----------------------
// | rkyv Implementation |
// -----------------------

#[cfg(feature = "rkyv")]
mod rkyv_impl {
    //! rkyv serialization types for peer info
    //!
    //! Contains remote type shims for types that don't natively support rkyv.

    use libp2p::Multiaddr;
    use rkyv::{Archive, Deserialize, Serialize};

    // ----------------
    // | MultiaddrDef |
    // ----------------

    /// Remote type shim for `libp2p::Multiaddr`
    #[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
    #[rkyv(derive(Debug), compare(PartialEq))]
    #[rkyv(remote = libp2p::Multiaddr)]
    #[rkyv(archived = ArchivedMultiaddr)]
    pub struct MultiaddrDef {
        /// The underlying bytes of the multiaddr.
        #[rkyv(getter = Multiaddr::to_vec)]
        pub bytes: Vec<u8>,
    }

    impl From<MultiaddrDef> for Multiaddr {
        fn from(value: MultiaddrDef) -> Self {
            Multiaddr::try_from(value.bytes).expect("Invalid Multiaddr bytes")
        }
    }

    impl PartialEq<Multiaddr> for ArchivedMultiaddr {
        fn eq(&self, other: &Multiaddr) -> bool {
            self.bytes.as_slice() == other.to_vec().as_slice()
        }
    }
}

#[cfg(feature = "rkyv")]
pub use rkyv_impl::MultiaddrDef;
