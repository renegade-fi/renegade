//! Cryptographic primitive types for the API

#[cfg(feature = "full-api")]
use circuit_types::baby_jubjub::BabyJubJubPointShare;
#[cfg(feature = "full-api")]
use circuit_types::schnorr::SchnorrPublicKeyShare;
use circuit_types::{
    baby_jubjub::BabyJubJubPoint,
    schnorr::{SchnorrPublicKey, SchnorrSignature},
};
use constants::{EmbeddedScalarField, Scalar};
use darkpool_types::csprng::PoseidonCSPRNG;
use serde::{Deserialize, Serialize};

use crate::serde_helpers;

// -----------------------
// | Cryptographic Types |
// -----------------------

/// A Poseidon-based CSPRNG state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiPoseidonCSPRNG {
    /// The seed of the CSPRNG
    #[serde(with = "serde_helpers::scalar_as_string")]
    pub seed: Scalar,
    /// The current index of the CSPRNG
    pub index: u64,
}

impl From<PoseidonCSPRNG> for ApiPoseidonCSPRNG {
    fn from(csprng: PoseidonCSPRNG) -> Self {
        Self { seed: csprng.seed, index: csprng.index }
    }
}

impl From<ApiPoseidonCSPRNG> for PoseidonCSPRNG {
    fn from(csprng: ApiPoseidonCSPRNG) -> Self {
        PoseidonCSPRNG { seed: csprng.seed, index: csprng.index }
    }
}

/// A Baby JubJub curve point
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiBabyJubJubPoint {
    /// The x-coordinate
    #[serde(with = "serde_helpers::scalar_as_string")]
    pub x: Scalar,
    /// The y-coordinate
    #[serde(with = "serde_helpers::scalar_as_string")]
    pub y: Scalar,
}

impl From<BabyJubJubPoint> for ApiBabyJubJubPoint {
    fn from(point: BabyJubJubPoint) -> Self {
        Self { x: point.x, y: point.y }
    }
}

impl From<ApiBabyJubJubPoint> for BabyJubJubPoint {
    fn from(point: ApiBabyJubJubPoint) -> Self {
        BabyJubJubPoint { x: point.x, y: point.y }
    }
}

/// A Schnorr signature over a Baby JubJub curve
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiSchnorrSignature {
    /// The embedded scalar component of the signature
    #[serde(with = "serde_helpers::embedded_scalar_as_string")]
    pub s: EmbeddedScalarField,
    /// The point component of the signature
    pub r: ApiBabyJubJubPoint,
}

impl From<ApiSchnorrSignature> for SchnorrSignature {
    fn from(signature: ApiSchnorrSignature) -> Self {
        SchnorrSignature { s: signature.s, r: signature.r.into() }
    }
}

impl From<SchnorrSignature> for ApiSchnorrSignature {
    fn from(signature: SchnorrSignature) -> Self {
        Self { s: signature.s, r: signature.r.into() }
    }
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

impl From<ApiSchnorrPublicKey> for SchnorrPublicKey {
    fn from(key: ApiSchnorrPublicKey) -> Self {
        SchnorrPublicKey { point: key.point.into() }
    }
}

/// A share of a Schnorr public key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiSchnorrPublicKeyShare {
    /// The x-coordinate share
    #[serde(with = "serde_helpers::scalar_as_string")]
    pub x: Scalar,
    /// The y-coordinate share
    #[serde(with = "serde_helpers::scalar_as_string")]
    pub y: Scalar,
}

#[cfg(feature = "full-api")]
impl From<SchnorrPublicKeyShare> for ApiSchnorrPublicKeyShare {
    fn from(share: SchnorrPublicKeyShare) -> Self {
        Self { x: share.point.x, y: share.point.y }
    }
}

#[cfg(feature = "full-api")]
impl From<ApiSchnorrPublicKeyShare> for SchnorrPublicKeyShare {
    fn from(share: ApiSchnorrPublicKeyShare) -> Self {
        SchnorrPublicKeyShare { point: BabyJubJubPointShare { x: share.x, y: share.y } }
    }
}
