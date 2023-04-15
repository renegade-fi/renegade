//! Defines the constraint system types for the set of keys a wallet holds

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use mpc_bulletproof::r1cs::{Prover, RandomizableConstraintSystem, Variable, Verifier};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::{
    types::{scalar_from_hex_string, scalar_to_hex_string},
    zk_gadgets::nonnative::{
        NonNativeElement, NonNativeElementCommitment, NonNativeElementVar, TWO_TO_256_FIELD_MOD,
    },
    CommitPublic, CommitVerifier, CommitWitness,
};

use super::{biguint_from_hex_string, biguint_to_hex_string};

/// The number of keys held in a wallet's keychain
pub const NUM_KEYS: usize = 4;

// -------------
// | Key Types |
// -------------

/// A public identification key is the image-under-hash of the secret identification key
/// knowledge of which is proved in a circuit
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PublicIdentificationKey(pub(crate) Scalar);
impl Serialize for PublicIdentificationKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        scalar_to_hex_string(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for PublicIdentificationKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let scalar = scalar_from_hex_string(deserializer)?;
        Ok(Self(scalar))
    }
}

impl CommitWitness for PublicIdentificationKey {
    type VarType = Variable;
    type CommitType = CompressedRistretto;
    type ErrorType = (); // Does not error

    fn commit_witness<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        self.0.commit_witness(rng, prover)
    }
}

impl From<Scalar> for PublicIdentificationKey {
    fn from(key: Scalar) -> Self {
        Self(key)
    }
}

impl From<PublicIdentificationKey> for Scalar {
    fn from(key: PublicIdentificationKey) -> Self {
        key.0
    }
}

/// A secret identification key is the hash preimage of the public identification key
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SecretIdentificationKey(pub(crate) Scalar);
impl Serialize for SecretIdentificationKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        scalar_to_hex_string(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for SecretIdentificationKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let val = scalar_from_hex_string(deserializer)?;
        Ok(Self(val))
    }
}

impl CommitWitness for SecretIdentificationKey {
    type VarType = Variable;
    type CommitType = CompressedRistretto;
    type ErrorType = ();

    fn commit_witness<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        self.0.commit_witness(rng, prover)
    }
}

impl From<Scalar> for SecretIdentificationKey {
    fn from(key: Scalar) -> Self {
        Self(key)
    }
}

impl From<SecretIdentificationKey> for Scalar {
    fn from(key: SecretIdentificationKey) -> Self {
        key.0
    }
}

/// A public signing key is a public EdDSA key over curve25519, serialized to a BigUint
///
/// The type is committed to as a NonNativeVar to support keys larger than the
/// proof system's field size
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicSigningKey(pub(crate) BigUint);
impl Serialize for PublicSigningKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        biguint_to_hex_string(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for PublicSigningKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let val = biguint_from_hex_string(deserializer)?;
        Ok(Self(val))
    }
}

impl CommitWitness for PublicSigningKey {
    type VarType = NonNativeElementVar;
    type CommitType = NonNativeElementCommitment;
    type ErrorType = (); // Does not error

    fn commit_witness<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let nonnative_key = NonNativeElement {
            val: self.0.clone(),
            field_mod: TWO_TO_256_FIELD_MOD.clone(),
        };

        nonnative_key.commit_witness(rng, prover)
    }
}

impl CommitPublic for PublicSigningKey {
    type VarType = NonNativeElementVar;
    type ErrorType = (); // Does not error

    fn commit_public<CS: RandomizableConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Result<Self::VarType, Self::ErrorType> {
        let nonnative_key = NonNativeElement {
            val: self.0.clone(),
            field_mod: TWO_TO_256_FIELD_MOD.clone(),
        };

        nonnative_key.commit_public(cs)
    }
}

impl From<BigUint> for PublicSigningKey {
    fn from(key: BigUint) -> Self {
        Self(key)
    }
}

impl From<PublicSigningKey> for Vec<Scalar> {
    fn from(key: PublicSigningKey) -> Self {
        // Get the word representation of the non-native key
        let elem = NonNativeElement {
            val: key.0,
            field_mod: TWO_TO_256_FIELD_MOD.clone(),
        };

        elem.into()
    }
}

/// A secret signing key is a secret EdDSA key over curve25519, serialized as bigint
///
/// The type is committed to as a NonNativeVar to support keys larger than the
/// proof system's field size
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretSigningKey(pub(crate) BigUint);
impl Serialize for SecretSigningKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        biguint_to_hex_string(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for SecretSigningKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let val = biguint_from_hex_string(deserializer)?;
        Ok(Self(val))
    }
}

impl From<BigUint> for SecretSigningKey {
    fn from(key: BigUint) -> Self {
        Self(key)
    }
}

impl CommitWitness for SecretSigningKey {
    type VarType = NonNativeElementVar;
    type CommitType = NonNativeElementCommitment;
    type ErrorType = (); // Does not error

    fn commit_witness<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let nonnative_key = NonNativeElement {
            val: self.0.clone(),
            field_mod: TWO_TO_256_FIELD_MOD.clone(),
        };

        nonnative_key.commit_witness(rng, prover)
    }
}

/// A public encryption key is an ElGamal key over the Scalar field, this is likely
/// to change in the near future to an elliptic curve non-native implementation
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PublicEncryptionKey(pub(crate) Scalar);
impl Serialize for PublicEncryptionKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        scalar_to_hex_string(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for PublicEncryptionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let val = scalar_from_hex_string(deserializer)?;
        Ok(Self(val))
    }
}

impl CommitWitness for PublicEncryptionKey {
    type VarType = Variable;
    type CommitType = CompressedRistretto;
    type ErrorType = (); // Does not error

    fn commit_witness<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        self.0.commit_witness(rng, prover)
    }
}

impl From<Scalar> for PublicEncryptionKey {
    fn from(key: Scalar) -> Self {
        Self(key)
    }
}

impl From<PublicEncryptionKey> for Scalar {
    fn from(key: PublicEncryptionKey) -> Self {
        key.0
    }
}

/// A secret encryption key is an ElGamal key over the Scalar field, this is likely
/// to change in the near future to an elliptic curve non-native implementation
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SecretEncryptionKey(pub(crate) Scalar);
impl Serialize for SecretEncryptionKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        scalar_to_hex_string(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for SecretEncryptionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let val = scalar_from_hex_string(deserializer)?;
        Ok(Self(val))
    }
}

impl From<Scalar> for SecretEncryptionKey {
    fn from(val: Scalar) -> Self {
        Self(val)
    }
}

impl From<SecretEncryptionKey> for Scalar {
    fn from(val: SecretEncryptionKey) -> Self {
        val.0
    }
}

impl CommitWitness for SecretEncryptionKey {
    type VarType = Variable;
    type CommitType = CompressedRistretto;
    type ErrorType = (); // Does not error

    fn commit_witness<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        self.0.commit_witness(rng, prover)
    }
}

// -----------------
// | Keychain Type |
// -----------------

/// Represents the base type, defining four keys with various access levels
///
/// Note that these keys are of different types, though over the same field
///     - `pk_root` is the public root key, the secret key is used as a signing key
///     - `pk_match` is the public match key, it is used as an identification key
///        authorizing a holder of `sk_match` to match orders in the wallet
///     - `pk_settle` is the public settle key it is used as an identification key
///        authorizing a holder of `sk_settle` to settle notes into the wallet
///     - `pk_view` is the public view key, it is used as an encryption key, holders
///        of `sk_view` may decrypt wallet and note ciphertexts related to this wallet
///
/// When we say identification key, we are talking about an abstract, zero-knowledge
/// identification scheme (not necessarily a signature scheme). Concretely, this currently
/// is setup as `pk_identity` = Hash(`sk_identity`), and the prover proves knowledge of
/// pre-image in a related circuit
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyChain {
    /// The public root key
    pub pk_root: PublicSigningKey,
    /// The public match key
    pub pk_match: PublicIdentificationKey,
    /// The public settle key
    pub pk_settle: PublicIdentificationKey,
    /// The public view key
    pub pk_view: PublicEncryptionKey,
}

/// Represents a keychain that has been allocated in a single-prover constraint system
#[derive(Clone, Debug)]
pub struct PublicKeyChainVar {
    /// The public root key
    pub pk_root: NonNativeElementVar,
    /// The public match key
    pub pk_match: Variable,
    /// The public settle key
    pub pk_settle: Variable,
    /// The public view key
    pub pk_view: Variable,
}

/// Represents a commitment to a keychain that has been allocated in a single-prover constraint system
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommittedPublicKeyChain {
    /// The public root key
    pub pk_root: NonNativeElementCommitment,
    /// The public match key
    pub pk_match: CompressedRistretto,
    /// The public settle key
    pub pk_settle: CompressedRistretto,
    /// The public view key
    pub pk_view: CompressedRistretto,
}

impl CommitWitness for PublicKeyChain {
    type VarType = PublicKeyChainVar;
    type CommitType = CommittedPublicKeyChain;
    type ErrorType = ();

    fn commit_witness<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (root_var, root_comm) = self.pk_root.commit_witness(rng, prover).unwrap();
        let (match_var, match_comm) = self.pk_match.commit_witness(rng, prover).unwrap();
        let (settle_var, settle_comm) = self.pk_settle.commit_witness(rng, prover).unwrap();
        let (view_var, view_comm) = self.pk_view.commit_witness(rng, prover).unwrap();

        Ok((
            PublicKeyChainVar {
                pk_root: root_var,
                pk_match: match_var,
                pk_settle: settle_var,
                pk_view: view_var,
            },
            CommittedPublicKeyChain {
                pk_root: root_comm,
                pk_match: match_comm,
                pk_settle: settle_comm,
                pk_view: view_comm,
            },
        ))
    }
}

impl CommitVerifier for CommittedPublicKeyChain {
    type VarType = PublicKeyChainVar;
    type ErrorType = ();

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let root_var = self.pk_root.commit_verifier(verifier).unwrap();
        let match_var = verifier.commit(self.pk_match);
        let settle_var = verifier.commit(self.pk_settle);
        let view_var = verifier.commit(self.pk_view);

        Ok(PublicKeyChainVar {
            pk_root: root_var,
            pk_match: match_var,
            pk_settle: settle_var,
            pk_view: view_var,
        })
    }
}

/// Tests for the KeyChain type
#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;
    use num_bigint::RandBigInt;
    use rand::thread_rng;
    use rand_core::OsRng;

    use crate::types::keychain::PublicKeyChain;

    #[test]
    fn test_serde() {
        let mut rng = OsRng {};
        let mut rng2 = thread_rng();

        let keychain = PublicKeyChain {
            pk_root: rng2.gen_biguint(256 /* bit_size */).into(),
            pk_match: Scalar::random(&mut rng).into(),
            pk_settle: Scalar::random(&mut rng).into(),
            pk_view: Scalar::random(&mut rng).into(),
        };

        let serialized = serde_json::to_string(&keychain).unwrap();
        let deserialized: PublicKeyChain = serde_json::from_str(&serialized).unwrap();

        assert_eq!(keychain, deserialized);
    }
}
