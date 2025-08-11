//! Config validation

use crate::RelayerConfig;
use ed25519_dalek::{Digest, Keypair as DalekKeypair, Sha512, SignatureError};
use std::path::Path;

/// The dummy message used for checking elliptic curve key pairs
const DUMMY_MESSAGE: &str = "signature check";

/// Validate a parsed config
pub fn validate_config(config: &RelayerConfig) -> Result<(), String> {
    // The raft snapshot dir must be an absolute path
    let snap_path = Path::new(&config.raft_snapshot_path);
    if !snap_path.is_absolute() {
        return Err("`raft-snapshot-path` must be an absolute path".to_string());
    }

    // Verify that the keypair represents a valid elliptic curve pair
    if validate_cluster_keypair(&config.cluster_keypair).is_err() {
        return Err("`cluster-keypair` is not a valid keypair".to_string());
    }

    Ok(())
}

/// Runtime validation of the keypair passed into the relayer via config
/// Sign a simple request and verify the signature
///
/// The public interface does not allow us to more directly check the keypair
/// as public_key == private_key * ed25519_generator, so we opt for this
/// instead. Happens once at startup so we are not concerned with performance
fn validate_cluster_keypair(keypair: &DalekKeypair) -> Result<(), SignatureError> {
    // Hash the message
    let mut hash_digest: Sha512 = Sha512::new();
    hash_digest.update(DUMMY_MESSAGE);

    // Sign and verify with keypair
    let sig = keypair.sign_prehashed(hash_digest, None /* context */).unwrap();

    // Rehash, hashes are not clone-able
    let mut second_hash: Sha512 = Sha512::new();
    second_hash.update(DUMMY_MESSAGE);
    keypair.verify_prehashed(second_hash, None /* context */, &sig)
}
