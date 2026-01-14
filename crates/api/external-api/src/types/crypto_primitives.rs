//! Cryptographic primitive types for the API

use circuit_types::{baby_jubjub::BabyJubJubPoint, schnorr::SchnorrPublicKey};
#[cfg(feature = "full-api")]
use circuit_types::schnorr::SchnorrPublicKeyShare;
use darkpool_types::csprng::PoseidonCSPRNG;
use serde::{Deserialize, Serialize};

// -----------------------
// | Cryptographic Types |
// -----------------------

/// A Poseidon-based CSPRNG state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiPoseidonCSPRNG {
    /// The seed of the CSPRNG
    pub seed: String,
    /// The current index of the CSPRNG
    pub index: u64,
}

impl From<PoseidonCSPRNG> for ApiPoseidonCSPRNG {
    fn from(csprng: PoseidonCSPRNG) -> Self {
        Self { seed: csprng.seed.to_string(), index: csprng.index }
    }
}

/// A Baby JubJub curve point
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiBabyJubJubPoint {
    /// The x-coordinate
    pub x: String,
    /// The y-coordinate
    pub y: String,
}

impl From<BabyJubJubPoint> for ApiBabyJubJubPoint {
    fn from(point: BabyJubJubPoint) -> Self {
        Self { x: point.x.to_string(), y: point.y.to_string() }
    }
}

/// A Schnorr signature over a Baby JubJub curve
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiSchnorrSignature {
    /// The scalar component of the signature
    pub s: String,
    /// The point component of the signature
    pub r: ApiBabyJubJubPoint,
}

/// A Schnorr public key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiSchnorrPublicKey {
    /// The curve point
    pub point: ApiBabyJubJubPoint,
}

impl From<SchnorrPublicKey> for ApiSchnorrPublicKey {
    fn from(key: SchnorrPublicKey) -> Self {
        Self { point: key.point.into() }
    }
}

/// A share of a Schnorr public key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiSchnorrPublicKeyShare {
    /// The x-coordinate share
    pub x: String,
    /// The y-coordinate share
    pub y: String,
}

#[cfg(feature = "full-api")]
impl From<SchnorrPublicKeyShare> for ApiSchnorrPublicKeyShare {
    fn from(share: SchnorrPublicKeyShare) -> Self {
        Self {
            x: share.point.x.to_string(),
            y: share.point.y.to_string(),
        }
    }
}
