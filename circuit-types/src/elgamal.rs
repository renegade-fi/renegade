//! Types for ElGamal-EC over BabyJubJub
#![allow(missing_docs)]

use ark_ec::{
    twisted_edwards::{Projective, TECurveConfig},
    CurveGroup, Group,
};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bigdecimal::Num;
use constants::{
    EmbeddedCurveConfig, EmbeddedCurveGroup, EmbeddedCurveGroupAffine, EmbeddedScalarField, Scalar,
    ScalarField,
};
use itertools::Itertools;
use num_bigint::BigUint;
use rand::{CryptoRng, Rng};
use renegade_crypto::fields::biguint_to_jubjub;
use serde::{ser::SerializeSeq, Deserialize, Serialize, Serializer};
use std::ops::Add;

use crate::{deserialize_array, serialize_array};

#[cfg(feature = "proof-system-types")]
use {
    crate::{
        traits::{
            BaseType, CircuitBaseType, CircuitVarType, MpcBaseType, MpcType,
            MultiproverCircuitBaseType, SecretShareBaseType, SecretShareType, SecretShareVarType,
        },
        Fabric,
    },
    circuit_macros::circuit_type,
    constants::AuthenticatedScalar,
    jf_primitives::{
        circuit::elgamal::ElGamalHybridCtxtVars,
        elgamal::{Ciphertext, DecKey, EncKey},
    },
    mpc_relation::{gadgets::ecc::PointVariable, traits::Circuit, Variable},
};

// ---------------------
// | ElGamal Key Types |
// ---------------------

/// A type alias representing an encryption key in the ElGamal over BabyJubJub
/// crypto-system
pub type EncryptionKey = BabyJubJubPoint;
/// A type alias for an encryption key allocated in a constraint system
#[cfg(feature = "proof-system-types")]
pub type EncryptionKeyVar = BabyJubJubPointVar;

#[cfg_attr(feature = "proof-system-types", circuit_type(serde, singleprover_circuit))]
#[derive(Copy, Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DecryptionKey {
    /// The underlying scalar field element
    pub key: EmbeddedScalarField,
}

impl DecryptionKey {
    /// Parse a decryption key from a hex string
    pub fn from_hex_str(s: &str) -> Result<Self, String> {
        let stripped = s.strip_prefix("0x").unwrap_or(s);
        let key_bigint =
            BigUint::from_str_radix(stripped, 16 /* radix */).map_err(|e| e.to_string())?;

        Ok(Self { key: biguint_to_jubjub(&key_bigint) })
    }

    /// Get the public encryption key associated with this decryption key
    pub fn public_key(&self) -> EncryptionKey {
        let inner = EmbeddedCurveGroup::generator() * self.key;
        EncryptionKey::from(inner)
    }

    /// Generate a new random decryption key
    pub fn random<R: Rng + CryptoRng>(r: &mut R) -> Self {
        Self { key: EmbeddedScalarField::rand(r) }
    }

    /// Generate a new random decryption key and return the associated
    /// encryption keypair
    pub fn random_pair<R: Rng + CryptoRng>(r: &mut R) -> (Self, EncryptionKey) {
        let dec_key = Self::random(r);
        let enc_key = dec_key.public_key();

        (dec_key, enc_key)
    }
}

impl Serialize for DecryptionKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::new();
        self.serialize_compressed(&mut bytes).unwrap();

        // Serialize explicitly as a sequence to avoid issues with serde formats
        let mut seq = serializer.serialize_seq(Some(bytes.len()))?;
        for byte in bytes.iter() {
            seq.serialize_element(byte)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for DecryptionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        Self::deserialize_compressed(bytes.as_slice()).map_err(serde::de::Error::custom)
    }
}

/// The affine representation of a point on the BabyJubJub curve
#[cfg_attr(
    feature = "proof-system-types",
    circuit_type(serde, singleprover_circuit, secret_share, mpc, multiprover_circuit)
)]
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BabyJubJubPoint {
    /// The x coordinate of the point
    pub x: Scalar,
    /// The y coordinate of the point
    pub y: Scalar,
}

impl BabyJubJubPoint {
    /// Check that the point is on the curve
    pub fn is_on_curve(&self) -> bool {
        let affine = EmbeddedCurveGroupAffine::new_unchecked(self.x.inner(), self.y.inner());
        affine.is_on_curve()
    }
}

impl Default for BabyJubJubPoint {
    fn default() -> Self {
        // The group generator
        let gen = EmbeddedCurveConfig::GENERATOR;
        let x = Scalar::new(gen.x);
        let y = Scalar::new(gen.y);

        BabyJubJubPoint { x, y }
    }
}

impl From<Projective<EmbeddedCurveConfig>> for BabyJubJubPoint {
    fn from(value: Projective<EmbeddedCurveConfig>) -> Self {
        let affine = value.into_affine();
        BabyJubJubPoint { x: Scalar::new(affine.x), y: Scalar::new(affine.y) }
    }
}

impl From<BabyJubJubPoint> for Projective<EmbeddedCurveConfig> {
    fn from(value: BabyJubJubPoint) -> Self {
        let x = value.x.inner();
        let y = value.y.inner();

        Projective::from(EmbeddedCurveGroupAffine::new(x, y))
    }
}

#[cfg(feature = "proof-system-types")]
impl From<EncKey<EmbeddedCurveConfig>> for EncryptionKey {
    fn from(key: EncKey<EmbeddedCurveConfig>) -> Self {
        Self::from(key.key)
    }
}

#[cfg(feature = "proof-system-types")]
impl From<EncryptionKey> for EncKey<EmbeddedCurveConfig> {
    fn from(value: EncryptionKey) -> Self {
        EncKey { key: value.into() }
    }
}

#[cfg(feature = "proof-system-types")]
impl From<DecKey<EmbeddedCurveConfig>> for DecryptionKey {
    fn from(value: DecKey<EmbeddedCurveConfig>) -> Self {
        DecryptionKey { key: value.key }
    }
}

#[cfg(feature = "proof-system-types")]
impl From<DecryptionKey> for DecKey<EmbeddedCurveConfig> {
    fn from(value: DecryptionKey) -> Self {
        DecKey { key: value.key }
    }
}

#[cfg(feature = "proof-system-types")]
impl From<BabyJubJubPointVar> for PointVariable {
    fn from(value: BabyJubJubPointVar) -> Self {
        PointVariable(value.x, value.y)
    }
}

#[cfg(feature = "proof-system-types")]
impl From<PointVariable> for BabyJubJubPointVar {
    fn from(value: PointVariable) -> Self {
        BabyJubJubPointVar { x: value.0, y: value.1 }
    }
}

// --------------------
// | Ciphertext Types |
// --------------------

/// A ciphertext in the EC-ElGamal cryptosystem
///
/// We use a hybrid encryption scheme in which the plaintext is encrypted under
/// a pad generated by a stream cipher. The stream is seeded by the coordinates
/// of the ephemeral key
#[cfg_attr(
    feature = "proof-system-types",
    circuit_type(serde, singleprover_circuit, secret_share, mpc, multiprover_circuit)
)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ElGamalCiphertext<const N: usize> {
    /// The ephemeral key
    pub ephemeral_key: BabyJubJubPoint,
    /// The ciphertext
    #[serde(serialize_with = "serialize_array", deserialize_with = "deserialize_array")]
    pub ciphertext: [Scalar; N],
}

impl<const N: usize> ElGamalCiphertext<N> {
    /// Check that the ciphertext is valid
    ///
    /// Currently this only checks that the ephemeral key is on the curve
    pub fn is_valid_ciphertext(&self) -> bool {
        self.ephemeral_key.is_on_curve()
    }
}

/// Conversion from `jf-primitives` types
#[cfg(feature = "proof-system-types")]
impl<const N: usize> From<ElGamalHybridCtxtVars> for ElGamalCiphertextVar<N> {
    fn from(value: ElGamalHybridCtxtVars) -> Self {
        let ephemeral_key = value.ephemeral.into();
        let ciphertext = value.symm_ctxts.try_into().expect("Invalid ciphertext size");

        Self { ephemeral_key, ciphertext }
    }
}

#[cfg(feature = "proof-system-types")]
impl<const N: usize> From<Ciphertext<EmbeddedCurveConfig>> for ElGamalCiphertext<N> {
    fn from(value: Ciphertext<EmbeddedCurveConfig>) -> Self {
        let ephemeral_key = value.ephemeral.into();
        let ciphertext = value
            .data
            .into_iter()
            .map(Scalar::new)
            .collect_vec()
            .try_into()
            .expect("Invalid ciphertext size");

        Self { ephemeral_key, ciphertext }
    }
}

#[cfg(feature = "proof-system-types")]
impl<const N: usize> From<ElGamalCiphertext<N>> for Ciphertext<EmbeddedCurveConfig> {
    fn from(value: ElGamalCiphertext<N>) -> Self {
        let ephemeral = value.ephemeral_key.into();
        let data = value.ciphertext.iter().map(Scalar::inner).collect_vec();

        Ciphertext { ephemeral, data }
    }
}
