//! Cluster identification and authentication types

use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    ops::Deref,
    str::FromStr,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as b64_standard};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, SignatureError};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use util::raw_err_str;

/// The topic prefix for the cluster management pubsub topic
///
/// The actual topic name will have the cluster ID postfixed; i.e.
///     cluster-management-{cluster_id}
pub const CLUSTER_MANAGEMENT_TOPIC_PREFIX: &str = "cluster-management";

/// A type alias for the cluster identifier
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct ClusterId(String);

impl ClusterId {
    /// Construct a clusterID, it's more readable and debuggable to compress the
    /// public key into a base64 encoded representation than to use the value
    /// directly
    pub fn new(cluster_pubkey: &PublicKey) -> Self {
        #[allow(deprecated)]
        let encoded_key = base64::encode(cluster_pubkey.as_bytes());
        Self(encoded_key)
    }

    /// Get the cluster management pubsub topic name for the cluster identified
    pub fn get_management_topic(&self) -> String {
        format!("{CLUSTER_MANAGEMENT_TOPIC_PREFIX}-{}", self.0)
    }

    /// Get the public key represented by this cluster
    pub fn get_public_key(&self) -> Result<PublicKey, SignatureError> {
        #[allow(deprecated)]
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

impl ClusterId {
    /// Construct a ClusterId from a string (infallible)
    pub fn from_str_infallible(s: &str) -> Self {
        Self(s.to_string())
    }
}

#[cfg(feature = "rkyv")]
impl PartialEq<ClusterId> for ArchivedClusterId {
    fn eq(&self, other: &ClusterId) -> bool {
        self.0.as_str() == other.0.as_str()
    }
}

/// A wrapped cluster keypair which allows us to implement traits on the type
#[derive(Debug)]
pub struct ClusterAsymmetricKeypair(pub Keypair);

impl ClusterAsymmetricKeypair {
    /// Construct a new ClusterAsymmetricKeypair
    pub fn new(keypair: Keypair) -> Self {
        Self(keypair)
    }

    /// Get a cluster key from a base64 encoded string representing the secret
    /// key
    pub fn from_base64(s: &str) -> Result<Self, String> {
        // Decode the base64 string and pad it to the correct length
        let decoded =
            b64_standard.decode(s).map_err(raw_err_str!("error decoding cluster key: {}"))?;

        // Decompress the bytes into an Ed25519 keypair
        let secret = SecretKey::from_bytes(&decoded)
            .map_err(raw_err_str!("error decompressing cluster key: {}"))?;
        let public = PublicKey::from(&secret);
        let keypair = Keypair { secret, public };
        Ok(Self(keypair))
    }

    /// Generate a random cluster keypair
    pub fn random() -> Self {
        let mut rng = OsRng {};
        Self(Keypair::generate(&mut rng))
    }
}

impl Clone for ClusterAsymmetricKeypair {
    fn clone(&self) -> Self {
        let cloned = Keypair::from_bytes(&self.0.to_bytes()).unwrap();
        Self(cloned)
    }
}

impl Deref for ClusterAsymmetricKeypair {
    type Target = Keypair;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
