//! Defines the constraint system types for the set of keys a wallet holds
#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use std::ops::Add;

use ark_ec::models::short_weierstrass::Affine;
use ark_ff::fields::PrimeField;
use circuit_macros::circuit_type;
use lazy_static::lazy_static;
use mpc_bulletproof::r1cs::{LinearCombination, Variable};
use mpc_stark::{
    algebra::{
        authenticated_scalar::AuthenticatedScalarResult,
        authenticated_stark_point::AuthenticatedStarkPointOpenResult, scalar::Scalar,
        stark_curve::StarkPoint,
    },
    MpcFabric,
};
use num_bigint::BigUint;
use num_integer::Integer;
use rand::{CryptoRng, RngCore};
use renegade_crypto::fields::biguint_to_scalar;
use serde::{Deserialize, Serialize};

use crate::{
    scalar_from_hex_string, scalar_to_hex_string,
    traits::{
        BaseType, CircuitBaseType, CircuitCommitmentType, CircuitVarType, LinearCombinationLike,
        LinkableBaseType, LinkableType, MpcBaseType, MpcLinearCombinationLike, MpcType,
        MultiproverCircuitBaseType, MultiproverCircuitCommitmentType,
        MultiproverCircuitVariableType, SecretShareBaseType, SecretShareType, SecretShareVarType,
    },
};

/// The number of keys held in a wallet's keychain
pub const NUM_KEYS: usize = 4;
/// The number of scalar words needed to represent STARK curve base field element
pub const SCALAR_WORDS_PER_FELT: usize = 2;

lazy_static! {
    static ref TWO_TO_128: BigUint = BigUint::from(1u8) << 128;
}

// -------------
// | Key Types |
// -------------

/// A public identification key is the image-under-hash of the secret identification key
/// knowledge of which is proved in a circuit
#[circuit_type(singleprover_circuit, mpc, multiprover_circuit, linkable, secret_share)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PublicIdentificationKey {
    pub key: Scalar,
}

impl Serialize for PublicIdentificationKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        scalar_to_hex_string(&self.key, serializer)
    }
}

impl<'de> Deserialize<'de> for PublicIdentificationKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let scalar = scalar_from_hex_string(deserializer)?;
        Ok(Self { key: scalar })
    }
}

impl From<Scalar> for PublicIdentificationKey {
    fn from(key: Scalar) -> Self {
        Self { key }
    }
}

impl From<PublicIdentificationKey> for Scalar {
    fn from(val: PublicIdentificationKey) -> Self {
        val.key
    }
}

/// A secret identification key is the hash preimage of the public identification key
#[circuit_type(serde, singleprover_circuit)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SecretIdentificationKey {
    pub key: Scalar,
}

impl Serialize for SecretIdentificationKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        scalar_to_hex_string(&self.key, serializer)
    }
}

impl<'de> Deserialize<'de> for SecretIdentificationKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let val = scalar_from_hex_string(deserializer)?;
        Ok(Self { key: val })
    }
}

impl From<Scalar> for SecretIdentificationKey {
    fn from(key: Scalar) -> Self {
        Self { key }
    }
}

impl From<SecretIdentificationKey> for Scalar {
    fn from(val: SecretIdentificationKey) -> Self {
        val.key
    }
}

// -----------------
// | Keychain Type |
// -----------------

/// An ECDSA public key is an elliptic curve point (in our case a `StarkPoint`),
/// however, to distinguish from `StarkPoint`s that are used throughout the proof system
/// but not allocated in the circuits, we represent the point by its affine coordinates.
///
/// Since the affine coordinates are elements of the base field, which is larger than the
/// scalar field, each coordinate is represented using 2 `Scalar`s (one for the lower 128 bits,
/// the other for the higher 128 bits).
#[circuit_type(
    serde,
    singleprover_circuit,
    mpc,
    multiprover_circuit,
    linkable,
    secret_share
)]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicSigningKey {
    pub x: [Scalar; SCALAR_WORDS_PER_FELT],
    pub y: [Scalar; SCALAR_WORDS_PER_FELT],
}

impl PublicSigningKey {
    /// Split a biguint into 128-bit scalar words
    fn split_biguint_into_words(val: &BigUint) -> [Scalar; SCALAR_WORDS_PER_FELT] {
        let (high, low) = BigUint::div_rem(val, &TWO_TO_128);

        [biguint_to_scalar(&low), biguint_to_scalar(&high)]
    }

    /// Combine 128-bit scalar words into a biguint
    fn combine_words_into_biguint(words: &[Scalar; SCALAR_WORDS_PER_FELT]) -> BigUint {
        let low_biguint = words[0].to_biguint();
        let high_biguint = words[1].to_biguint();

        (high_biguint << 128) + low_biguint
    }
}

impl From<StarkPoint> for PublicSigningKey {
    fn from(value: StarkPoint) -> Self {
        let Affine { x, y, infinity } = value.to_affine();
        assert!(!infinity, "public key cannot be additive identity");

        let x_biguint: BigUint = x.into_bigint().into();
        let x_words = Self::split_biguint_into_words(&x_biguint);
        let y_biguint: BigUint = y.into_bigint().into();
        let y_words = Self::split_biguint_into_words(&y_biguint);

        Self {
            x: x_words,
            y: y_words,
        }
    }
}

impl From<PublicSigningKey> for StarkPoint {
    fn from(value: PublicSigningKey) -> Self {
        let x = PublicSigningKey::combine_words_into_biguint(&value.x);
        let y = PublicSigningKey::combine_words_into_biguint(&value.y);
        StarkPoint::from_affine_coords(x, y)
    }
}

/// A type alias for readability
pub type SecretSigningKey = Scalar;

/// Represents the base type, defining two keys with different access levels
///
/// Note that these keys are of different types, though over the same field
///     - `pk_root` is the public root key, the secret key is used as a signing key
///     - `pk_match` is the public match key, it is used as an identification key
///        authorizing a holder of `sk_match` to match orders in the wallet
///
/// When we say identification key, we are talking about an abstract, zero-knowledge
/// identification scheme (not necessarily a signature scheme). Concretely, this currently
/// is setup as `pk_identity` = Hash(`sk_identity`), and the prover proves knowledge of
/// pre-image in a related circuit
#[circuit_type(
    serde,
    singleprover_circuit,
    mpc,
    multiprover_circuit,
    linkable,
    secret_share
)]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyChain {
    /// The public root key
    pub pk_root: PublicSigningKey,
    /// The public match key
    pub pk_match: PublicIdentificationKey,
}

#[cfg(test)]
mod test {
    use mpc_stark::{algebra::stark_curve::StarkPoint, random_point};

    use super::PublicSigningKey;

    #[test]
    fn test_pub_signing_key_to_from_starkpoint() {
        let rand_pt = random_point();

        // Convert to and from a nonnative key
        let pubkey: PublicSigningKey = rand_pt.into();
        let recovered_pt: StarkPoint = pubkey.into();

        assert_eq!(rand_pt, recovered_pt);
    }
}
