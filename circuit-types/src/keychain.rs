//! Defines the constraint system types for the set of keys a wallet holds
#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use std::ops::Add;

use circuit_macros::circuit_type;
use constants::{AuthenticatedScalar, Scalar, ScalarField};
use k256::{
    ecdsa::VerifyingKey as K256VerifyingKey,
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    AffinePoint, EncodedPoint, FieldElement as K256FieldElement,
};
use mpc_relation::{traits::Circuit, Variable};
use num_bigint::BigUint;
use renegade_crypto::fields::get_scalar_field_modulus;
use serde::{Deserialize, Serialize};

use crate::{
    scalar_from_hex_string, scalar_to_hex_string,
    traits::{
        BaseType, CircuitBaseType, CircuitVarType, MpcBaseType, MpcType,
        MultiproverCircuitBaseType, SecretShareBaseType, SecretShareType, SecretShareVarType,
    },
    Fabric,
};

use super::{biguint_from_hex_string, biguint_to_hex_string};

/// The number of keys held in a wallet's keychain
pub const NUM_KEYS: usize = 4;
/// The number of bytes used in a single scalar to represent a key
pub const SCALAR_MAX_BYTES: usize = 31;
/// The number of words needed to represent an element of k256's base field,
/// which is used to represent both public and private keys
const K256_FELT_WORDS: usize = 2;
/// The number of bytes in a k256 field element
const K256_FELT_BYTES: usize = 32;

// -------------
// | Key Types |
// -------------

/// A private identification key is the pre-image under a hash of its public key
pub type PrivateIdentificationKey = Scalar;

/// A public identification key is the image-under-hash of the secret
/// identification key knowledge of which is proved in a circuit
#[circuit_type(singleprover_circuit, mpc, multiprover_circuit, secret_share)]
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

/// A secret identification key is the hash preimage of the public
/// identification key
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

/// A non-native scalar is an element of a non-native field
/// (i.e. not Bn254 scalar)
#[circuit_type(serde, singleprover_circuit, mpc, multiprover_circuit, secret_share)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonNativeScalar<const SCALAR_WORDS: usize> {
    /// The native `Scalar` words used to represent the scalar
    ///
    /// Because the scalar is an element of a non-native field, its
    /// representation requires a bigint-like approach
    pub scalar_words: [Scalar; SCALAR_WORDS],
}

impl<const SCALAR_WORDS: usize> Default for NonNativeScalar<SCALAR_WORDS> {
    fn default() -> Self {
        Self { scalar_words: [Scalar::zero(); SCALAR_WORDS] }
    }
}

impl<const SCALAR_WORDS: usize> NonNativeScalar<SCALAR_WORDS> {
    /// Split a biguint into scalar words in little endian order
    fn split_biguint_into_words(mut val: BigUint) -> [Scalar; SCALAR_WORDS] {
        let scalar_mod = get_scalar_field_modulus();
        let mut res = Vec::with_capacity(SCALAR_WORDS);
        for _ in 0..SCALAR_WORDS {
            let word = Scalar::from(&val % &scalar_mod);
            val /= &scalar_mod;
            res.push(word);
        }

        res.try_into().unwrap()
    }

    /// Re-collect the key words into a biguint
    fn combine_words_into_biguint(&self) -> BigUint {
        let scalar_mod = get_scalar_field_modulus();
        self.scalar_words
            .iter()
            .rev()
            .fold(BigUint::from(0u8), |acc, word| acc * &scalar_mod + word.to_biguint())
    }
}

impl<const SCALAR_WORDS: usize> From<&BigUint> for NonNativeScalar<SCALAR_WORDS> {
    fn from(val: &BigUint) -> Self {
        Self { scalar_words: Self::split_biguint_into_words(val.clone()) }
    }
}

impl<const SCALAR_WORDS: usize> From<&NonNativeScalar<SCALAR_WORDS>> for BigUint {
    fn from(value: &NonNativeScalar<SCALAR_WORDS>) -> Self {
        value.combine_words_into_biguint()
    }
}

impl<const SCALAR_WORDS: usize> Serialize for NonNativeScalar<SCALAR_WORDS> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Recover a bigint from the scalar words
        biguint_to_hex_string(&self.into(), serializer)
    }
}

impl<'de, const SCALAR_WORDS: usize> Deserialize<'de> for NonNativeScalar<SCALAR_WORDS> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let val = biguint_from_hex_string(deserializer)?;
        Ok(Self::from(&val))
    }
}

impl From<&NonNativeScalar<K256_FELT_WORDS>> for K256FieldElement {
    fn from(value: &NonNativeScalar<K256_FELT_WORDS>) -> Self {
        let val_bigint = BigUint::from(value);
        let bytes: [u8; K256_FELT_BYTES] =
            val_bigint.to_bytes_be()[..K256_FELT_BYTES].try_into().unwrap();

        K256FieldElement::from_bytes(&bytes.into()).unwrap()
    }
}

impl From<&K256FieldElement> for NonNativeScalar<K256_FELT_WORDS> {
    fn from(value: &K256FieldElement) -> Self {
        let bytes = value.to_bytes();
        let val_bigint = BigUint::from_bytes_be(&bytes);

        Self::from(&val_bigint)
    }
}

// -----------------
// | Keychain Type |
// -----------------

/// A type alias for a private signing key
pub type PrivateSigningKey = NonNativeScalar<K256_FELT_WORDS>;

/// A public signing key in uncompressed affine representation
#[circuit_type(serde, singleprover_circuit, mpc, multiprover_circuit, secret_share)]
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PublicSigningKey {
    /// The affine x-coordinate of the public key
    pub x: NonNativeScalar<K256_FELT_WORDS>,
    /// The affine y-coordinate of the public key
    pub y: NonNativeScalar<K256_FELT_WORDS>,
}

impl PublicSigningKey {
    /// Construct a key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Parse the encoded K256 point assumed to be compressed
        let point = EncodedPoint::from_bytes(bytes).map_err(|e| e.to_string())?;

        // Convert to circuit-native types, it is simpler to go through the whole
        // conversion than decompressing manually
        let verifying_key =
            K256VerifyingKey::from_encoded_point(&point).map_err(|e| e.to_string())?;
        Ok((&verifying_key).into())
    }

    /// Convert the key to bytes
    pub fn to_compressed_bytes(&self) -> Vec<u8> {
        let verifying_key = K256VerifyingKey::from(self);
        verifying_key.to_sec1_bytes().to_vec()
    }
}

impl From<&PublicSigningKey> for K256VerifyingKey {
    fn from(value: &PublicSigningKey) -> Self {
        // Construct a point from the raw coordinates
        let x_coord = K256FieldElement::from(&value.x);
        let y_coord = K256FieldElement::from(&value.y);

        // `k256` does not expose direct access to coordinates except through a
        // compressed form
        let point = AffinePoint::from_encoded_point(&EncodedPoint::from_affine_coordinates(
            &x_coord.to_bytes(),
            &y_coord.to_bytes(),
            false, // compress
        ))
        .unwrap();

        K256VerifyingKey::from_affine(point).unwrap()
    }
}

impl From<&K256VerifyingKey> for PublicSigningKey {
    fn from(value: &K256VerifyingKey) -> Self {
        // Parse the coordinates of the affine representation of the key
        let encoded_key = value.as_affine().to_encoded_point(false /* compress */);
        let x_coord = K256FieldElement::from_bytes(encoded_key.x().unwrap()).unwrap();
        let y_coord = K256FieldElement::from_bytes(encoded_key.y().unwrap()).unwrap();

        // Convert to circuit-native types
        let x = NonNativeScalar::from(&x_coord);
        let y = NonNativeScalar::from(&y_coord);

        Self { x, y }
    }
}

/// A type alias for readability
pub type SecretSigningKey = NonNativeScalar<K256_FELT_WORDS>;

/// Represents the base type, defining two keys with different access levels
///
/// Note that these keys are of different types, though over the same field
///     - `pk_root` is the public root key, the secret key is used as a signing
///       key
///     - `pk_match` is the public match key, it is used as an identification
///       key authorizing a holder of `sk_match` to match orders in the wallet
///
/// When we say identification key, we are talking about an abstract,
/// zero-knowledge identification scheme (not necessarily a signature scheme).
/// Concretely, this currently is setup as `pk_identity` = Hash(`sk_identity`),
/// and the prover proves knowledge of pre-image in a related circuit
#[circuit_type(serde, singleprover_circuit, mpc, multiprover_circuit, secret_share)]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyChain {
    /// The public root key
    pub pk_root: PublicSigningKey,
    /// The public match key
    pub pk_match: PublicIdentificationKey,
}

#[cfg(test)]
mod test {
    use k256::ecdsa::{SigningKey, VerifyingKey};
    use num_bigint::BigUint;
    use rand::{thread_rng, RngCore};

    use super::{NonNativeScalar, PublicSigningKey};

    /// Tests converting a non-native key to and from a biguint
    #[test]
    fn test_nonnative_to_from_biguint() {
        let mut rng = rand::thread_rng();
        let mut buf = vec![0u8; 64 /* 512 bits */];
        rng.fill_bytes(&mut buf);

        // Convert to and from a nonnative key
        let random_biguint = BigUint::from_bytes_be(&buf);
        let key: NonNativeScalar<3 /* SCALAR_WORDS */> = (&random_biguint).into();
        let recovered_biguint: BigUint = (&key).into();

        assert_eq!(random_biguint, recovered_biguint);
    }

    /// Tests converting a signing key to and from the k256 library repr
    #[test]
    fn test_signing_key_conversions() {
        let mut rng = thread_rng();
        let key = SigningKey::random(&mut rng);
        let vkey = key.verifying_key();

        let circuit_key = PublicSigningKey::from(vkey);
        let recovered_vkey = VerifyingKey::from(&circuit_key);

        assert_eq!(*vkey, recovered_vkey);
    }
}
