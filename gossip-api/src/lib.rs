//! Defines API types for gossip within the p2p network

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use ed25519_dalek::{Digest, Keypair, PublicKey, Sha512, Signature, SignatureError};
use serde::Serialize;

pub mod pubsub;
pub mod request_response;

// -----------
// | Helpers |
// -----------

/// Sign a request body with the given key
pub fn sign_message<M: Serialize>(req: &M, key: &Keypair) -> Result<Vec<u8>, SignatureError> {
    let mut hash_digest = Sha512::new();
    hash_digest.update(&serde_json::to_vec(req).unwrap());
    let sig_bytes = key.sign_prehashed(hash_digest, None /* context */)?.to_bytes();

    Ok(sig_bytes.to_vec())
}

/// Check a signature on a request body with the given key
pub fn check_signature<M: Serialize>(
    req: &M,
    sig: &[u8],
    key: &PublicKey,
) -> Result<(), SignatureError> {
    let mut hash_digest = Sha512::new();
    hash_digest.update(&serde_json::to_vec(req).unwrap());
    let sig = Signature::from_bytes(sig)?;

    key.verify_prehashed(hash_digest, None /* context */, &sig)
}

/// The destination to which a request should be sent
pub enum GossipDestination {
    /// To the gossip server
    GossipServer,
    /// To the handshake manager
    HandshakeManager,
    /// Directly handled in the network layer
    NetworkManager,
}
