//! Gossip network types for the Renegade relayer
//!
//! This crate provides types for peer discovery and cluster management.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![deny(clippy::missing_docs_in_private_items)]

mod cluster;
mod handshake;
mod peer_id;
mod peer_info;

#[cfg(feature = "mocks")]
pub mod mocks;

// Re-exports
pub use cluster::{CLUSTER_MANAGEMENT_TOPIC_PREFIX, ClusterAsymmetricKeypair, ClusterId};
pub use handshake::ConnectionRole;
pub use peer_id::WrappedPeerId;
pub use peer_info::PeerInfo;

#[cfg(feature = "rkyv")]
pub use peer_info::MultiaddrDef;

#[cfg(test)]
mod tests {
    use ed25519_dalek::Keypair as DalekKeypair;
    use libp2p::{Multiaddr, PeerId, identity::Keypair};
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
