//! Types for Schnorr signatures
#![allow(missing_docs)]

use ark_ec::Group;
use ark_ff::UniformRand;
use circuit_macros::circuit_type;
use constants::{EmbeddedCurveConfig, EmbeddedCurveGroup, EmbeddedScalarField, Scalar};
use itertools::Itertools;
use jf_primitives::{
    circuit::signature::schnorr::{SignatureVar, VerKeyVar},
    errors::PrimitivesError,
    signatures::{
        SchnorrSignatureScheme, SignatureScheme,
        schnorr::{SignKey, Signature, VerKey},
    },
};
use rand::thread_rng;
use serde::{Deserialize, Serialize};

use crate::primitives::baby_jubjub::BabyJubJubPoint;
use crate::ser_embedded_scalar_field;
use crate::traits::BaseType;

#[cfg(feature = "proof-system-types")]
use {
    crate::traits::{
        CircuitBaseType, CircuitVarType, SecretShareBaseType, SecretShareType, SecretShareVarType,
    },
    constants::ScalarField,
    mpc_relation::gadgets::ecc::PointVariable,
    mpc_relation::{Variable, traits::Circuit},
    std::ops::Add,
};

// -------------
// | Signature |
// -------------

/// A Schnorr signature
#[cfg_attr(feature = "proof-system-types", circuit_type(serde, singleprover_circuit))]
#[cfg_attr(not(feature = "proof-system-types"), circuit_type(serde))]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchnorrSignature {
    /// The s-value of the signature
    ///
    /// s = H(M || r) * private_key + k
    #[serde(with = "ser_embedded_scalar_field")]
    pub s: EmbeddedScalarField,
    /// The R-value of the signature
    ///
    /// r = k * G for random k; though practically k is made deterministic via
    /// the transcript.
    pub r: BabyJubJubPoint,
}

impl From<Signature<EmbeddedCurveConfig>> for SchnorrSignature {
    fn from(sig: Signature<EmbeddedCurveConfig>) -> Self {
        Self { s: sig.s, r: sig.R.into() }
    }
}

impl From<SchnorrSignature> for Signature<EmbeddedCurveConfig> {
    fn from(sig: SchnorrSignature) -> Self {
        Signature { s: sig.s, R: sig.r.into() }
    }
}

#[cfg(feature = "proof-system-types")]
impl From<SchnorrSignatureVar> for SignatureVar {
    fn from(sig: SchnorrSignatureVar) -> Self {
        SignatureVar { s: sig.s, R: sig.r.into() }
    }
}

// ---------------
// | Private Key |
// ---------------

/// A Schnorr private key
#[cfg_attr(feature = "proof-system-types", circuit_type(serde, singleprover_circuit))]
#[cfg_attr(not(feature = "proof-system-types"), circuit_type(serde))]
#[derive(Copy, Clone, Debug)]
pub struct SchnorrPrivateKey {
    /// The underlying scalar field element
    pub inner: EmbeddedScalarField,
}

impl From<SchnorrPrivateKey> for SignKey<EmbeddedScalarField> {
    fn from(key: SchnorrPrivateKey) -> Self {
        SignKey(key.inner)
    }
}

impl SchnorrPrivateKey {
    /// Generate a random private key
    pub fn random() -> Self {
        let mut rng = thread_rng();
        let inner = EmbeddedScalarField::rand(&mut rng);
        Self { inner }
    }

    /// Get the public key corresponding to this private key
    pub fn public_key(&self) -> SchnorrPublicKey {
        let point = EmbeddedCurveGroup::generator() * self.inner;
        SchnorrPublicKey { point: BabyJubJubPoint::from(point) }
    }

    /// Sign a message with this private key
    pub fn sign<T: BaseType>(&self, message: &T) -> Result<SchnorrSignature, PrimitivesError> {
        let mut rng = thread_rng();
        let sk = SignKey::from(*self);
        let msg = message.to_scalars().iter().map(Scalar::inner).collect_vec();
        let sig = SchnorrSignatureScheme::<EmbeddedCurveConfig>::sign(
            &(), // Public Parameter
            &sk,
            msg,
            &mut rng,
        )?;

        Ok(sig.into())
    }
}

// --------------
// | Public Key |
// --------------

/// A Schnorr public key
#[cfg_attr(feature = "proof-system-types", circuit_type(serde, singleprover_circuit, secret_share))]
#[cfg_attr(not(feature = "proof-system-types"), circuit_type(serde))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchnorrPublicKey {
    /// The curve point representing the public key
    pub point: BabyJubJubPoint,
}

impl From<SchnorrPublicKey> for VerKey<EmbeddedCurveConfig> {
    fn from(key: SchnorrPublicKey) -> Self {
        VerKey(key.point.into())
    }
}

#[cfg(feature = "proof-system-types")]
impl From<SchnorrPublicKeyVar> for VerKeyVar {
    fn from(key: SchnorrPublicKeyVar) -> Self {
        VerKeyVar(PointVariable(key.point.x, key.point.y))
    }
}

impl SchnorrPublicKey {
    /// Verify a signature with this public key
    pub fn verify<T: BaseType>(&self, message: &T, signature: &SchnorrSignature) -> bool {
        let msg = message.to_scalars().iter().map(Scalar::inner).collect_vec();
        let sig = (*signature).into();
        let vk = (*self).into();
        SchnorrSignatureScheme::<EmbeddedCurveConfig>::verify(&(), &vk, &msg, &sig).is_ok()
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    use super::*;

    /// The message length to test with
    const MSG_LENGTH: usize = 10;

    /// Build a random message
    fn sample_message() -> [Scalar; MSG_LENGTH] {
        let mut rng = thread_rng();
        (0..MSG_LENGTH).map(|_| Scalar::random(&mut rng)).collect_vec().try_into().unwrap()
    }

    /// Tests verifying a valid signature
    #[test]
    fn test_schnorr_valid_verification() {
        let sk = SchnorrPrivateKey::random();
        let msg = sample_message();
        let sig = sk.sign(&msg).unwrap();

        // Verify the signature
        let pk = sk.public_key();
        let is_valid = pk.verify(&msg, &sig);
        assert!(is_valid);
    }

    /// Tests verifying an invalid signature
    #[test]
    fn test_schnorr_invalid_verification() {
        let sk = SchnorrPrivateKey::random();
        let msg = sample_message();
        let sig = sk.sign(&msg).unwrap();
        let pk = sk.public_key();

        // Verify with a different message
        let wrong_msg = sample_message();
        assert!(!pk.verify(&wrong_msg, &sig));

        // Verify with a different public key
        let wrong_sk = SchnorrPrivateKey::random();
        let wrong_pk = wrong_sk.public_key();
        assert!(!wrong_pk.verify(&msg, &sig));

        // Verify with a corrupted signature (modified s value)
        let mut corrupted_sig = sig;
        corrupted_sig.s += EmbeddedScalarField::from(1u64);
        assert!(!pk.verify(&msg, &corrupted_sig));
    }
}
