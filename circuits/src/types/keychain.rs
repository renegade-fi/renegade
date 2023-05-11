//! Defines the constraint system types for the set of keys a wallet holds

use std::ops::Add;

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use ed25519_dalek::PublicKey as DalekKey;
use itertools::Itertools;
use mpc_bulletproof::r1cs::{
    LinearCombination, Prover, RandomizableConstraintSystem, Variable, Verifier,
};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::{
    types::{scalar_from_hex_string, scalar_to_hex_string},
    zk_gadgets::nonnative::{
        LinkableNonNativeElementShare, NonNativeElement, NonNativeElementCommitment,
        NonNativeElementSecretShare, NonNativeElementSecretShareCommitment,
        NonNativeElementSecretShareVar, NonNativeElementVar, TWO_TO_256_FIELD_MOD,
    },
    CommitPublic, CommitVerifier, CommitWitness, LinkableCommitment,
};

use super::{biguint_from_hex_string, biguint_to_hex_string};

/// The number of keys held in a wallet's keychain
pub const NUM_KEYS: usize = 4;
/// The number of scalar words in a nonnative root key
pub const NUM_ROOT_KEY_WORDS: usize = 3;

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

impl CommitPublic for PublicIdentificationKey {
    type VarType = Variable;
    type ErrorType = (); // Does not error

    fn commit_public<CS: RandomizableConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Result<Self::VarType, Self::ErrorType> {
        self.0.commit_public(cs)
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

impl From<&PublicSigningKey> for DalekKey {
    fn from(key: &PublicSigningKey) -> Self {
        let key_bytes = key.0.to_bytes_le();
        DalekKey::from_bytes(&key_bytes).unwrap()
    }
}

impl From<DalekKey> for PublicSigningKey {
    fn from(key: DalekKey) -> Self {
        let key_bytes = key.as_bytes();
        Self(BigUint::from_bytes_le(key_bytes))
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

// -----------------
// | Keychain Type |
// -----------------

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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyChain {
    /// The public root key
    pub pk_root: PublicSigningKey,
    /// The public match key
    pub pk_match: PublicIdentificationKey,
}

/// Represents a keychain that has been allocated in a single-prover constraint system
#[derive(Clone, Debug)]
pub struct PublicKeyChainVar<L: Into<LinearCombination>> {
    /// The public root key
    pub pk_root: NonNativeElementVar,
    /// The public match key
    pub pk_match: L,
}

/// Represents a commitment to a keychain that has been allocated in a single-prover constraint system
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommittedPublicKeyChain {
    /// The public root key
    pub pk_root: NonNativeElementCommitment,
    /// The public match key
    pub pk_match: CompressedRistretto,
}

impl CommitWitness for PublicKeyChain {
    type VarType = PublicKeyChainVar<Variable>;
    type CommitType = CommittedPublicKeyChain;
    type ErrorType = ();

    fn commit_witness<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (root_var, root_comm) = self.pk_root.commit_witness(rng, prover).unwrap();
        let (match_var, match_comm) = self.pk_match.commit_witness(rng, prover).unwrap();

        Ok((
            PublicKeyChainVar {
                pk_root: root_var,
                pk_match: match_var,
            },
            CommittedPublicKeyChain {
                pk_root: root_comm,
                pk_match: match_comm,
            },
        ))
    }
}

impl CommitVerifier for CommittedPublicKeyChain {
    type VarType = PublicKeyChainVar<Variable>;
    type ErrorType = ();

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let root_var = self.pk_root.commit_verifier(verifier).unwrap();
        let match_var = verifier.commit(self.pk_match);

        Ok(PublicKeyChainVar {
            pk_root: root_var,
            pk_match: match_var,
        })
    }
}

// -------------------------------
// | Secret Shared Keychain Type |
// -------------------------------

/// Represents an additive secret share of a wallet's public keychain
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyChainSecretShare {
    /// The public root key
    pub pk_root: NonNativeElementSecretShare,
    /// The public match key
    pub pk_match: Scalar,
}

impl PublicKeyChainSecretShare {
    /// The number of `Scalars` it takes to represent secret shares of a keychain
    ///
    /// Equal to the number of `Scalar` words used to represent `pk_root` plus one
    /// for `pk_match`
    pub const SHARES_PER_KEYCHAIN: usize = NUM_ROOT_KEY_WORDS + 1;

    /// Apply a blinder to the secret shares
    pub fn blind(&mut self, blinder: Scalar) {
        self.pk_root.blind(blinder);
        self.pk_match += blinder;
    }

    /// Remove a blinder from the secret shares
    pub fn unblind(&mut self, blinder: Scalar) {
        self.pk_root.unblind(blinder);
        self.pk_match -= blinder;
    }
}

impl Add<PublicKeyChainSecretShare> for PublicKeyChainSecretShare {
    type Output = PublicKeyChain;

    fn add(self, rhs: PublicKeyChainSecretShare) -> Self::Output {
        let pk_root = self.pk_root + rhs.pk_root;
        let pk_match = self.pk_match + rhs.pk_match;

        PublicKeyChain {
            pk_root: PublicSigningKey(pk_root.val),
            pk_match: PublicIdentificationKey(pk_match),
        }
    }
}

// Keychain serialization
impl From<PublicKeyChainSecretShare> for Vec<Scalar> {
    fn from(keychain: PublicKeyChainSecretShare) -> Self {
        let mut root_words = keychain.pk_root.words;
        root_words.push(keychain.pk_match);

        root_words
    }
}

// Keychain deserialization
impl From<Vec<Scalar>> for PublicKeyChainSecretShare {
    fn from(mut serialized: Vec<Scalar>) -> Self {
        let root_words: Vec<Scalar> = serialized.drain(..NUM_ROOT_KEY_WORDS).collect();
        let pk_match = serialized.remove(0);

        PublicKeyChainSecretShare {
            pk_root: NonNativeElementSecretShare {
                words: root_words,
                field_mod: TWO_TO_256_FIELD_MOD.clone(),
            },
            pk_match,
        }
    }
}

/// Represents an additive secret share of a wallet's public keychain
/// that has been allocated in a constraint system
#[derive(Clone, Debug)]
pub struct PublicKeyChainSecretShareVar {
    /// The public root key
    pub pk_root: NonNativeElementSecretShareVar,
    /// The public match key
    pub pk_match: LinearCombination,
}

impl PublicKeyChainSecretShareVar {
    /// Apply a blinder to the secret shares
    pub fn blind(&mut self, blinder: LinearCombination) {
        self.pk_root.blind(blinder.clone());
        self.pk_match += blinder;
    }

    /// Remove a blinder from the secret shares
    pub fn unblind(&mut self, blinder: LinearCombination) {
        self.pk_root.unblind(blinder.clone());
        self.pk_match -= blinder;
    }
}

impl Add<PublicKeyChainSecretShareVar> for PublicKeyChainSecretShareVar {
    type Output = PublicKeyChainVar<LinearCombination>;

    fn add(self, rhs: PublicKeyChainSecretShareVar) -> Self::Output {
        let pk_root = self.pk_root + rhs.pk_root;
        let pk_match = self.pk_match + rhs.pk_match;

        PublicKeyChainVar { pk_root, pk_match }
    }
}

// Keychain share serialization
impl From<PublicKeyChainSecretShareVar> for Vec<LinearCombination> {
    fn from(keychain: PublicKeyChainSecretShareVar) -> Self {
        let mut root_words = keychain.pk_root.words;
        root_words.push(keychain.pk_match);

        root_words
    }
}

// Keychain share deserialization
impl<L: Into<LinearCombination>> From<Vec<L>> for PublicKeyChainSecretShareVar {
    fn from(mut serialized: Vec<L>) -> Self {
        let n_root_words = serialized.len() - 1;
        let root_words: Vec<LinearCombination> = serialized
            .drain(..n_root_words)
            .map(|word| word.into())
            .collect_vec();
        let pk_match = serialized.pop().unwrap();

        PublicKeyChainSecretShareVar {
            pk_root: NonNativeElementSecretShareVar {
                words: root_words,
                field_mod: TWO_TO_256_FIELD_MOD.clone(),
            },
            pk_match: pk_match.into(),
        }
    }
}

/// Represents a commitment to an additive secret share of a wallet's public keychain
/// that has been allocated in a constraint system
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKeyChainSecretShareCommitment {
    /// The public root key
    pub pk_root: NonNativeElementSecretShareCommitment,
    /// The public match key
    pub pk_match: CompressedRistretto,
}

impl CommitWitness for PublicKeyChainSecretShare {
    type VarType = PublicKeyChainSecretShareVar;
    type CommitType = PublicKeyChainSecretShareCommitment;
    type ErrorType = (); // Does not error

    fn commit_witness<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (root_var, root_comm) = self.pk_root.commit_witness(rng, prover).unwrap();
        let (match_var, match_comm) = self.pk_match.commit_witness(rng, prover).unwrap();

        Ok((
            PublicKeyChainSecretShareVar {
                pk_root: root_var,
                pk_match: match_var.into(),
            },
            PublicKeyChainSecretShareCommitment {
                pk_root: root_comm,
                pk_match: match_comm,
            },
        ))
    }
}

impl CommitPublic for PublicKeyChainSecretShare {
    type VarType = PublicKeyChainSecretShareVar;
    type ErrorType = (); // Does not error

    fn commit_public<CS: RandomizableConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Result<Self::VarType, Self::ErrorType> {
        let root_var = self.pk_root.commit_public(cs).unwrap();
        let match_var = self.pk_match.commit_public(cs).unwrap();

        Ok(PublicKeyChainSecretShareVar {
            pk_root: root_var,
            pk_match: match_var.into(),
        })
    }
}

impl CommitVerifier for PublicKeyChainSecretShareCommitment {
    type VarType = PublicKeyChainSecretShareVar;
    type ErrorType = (); // Does not error

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let root_var = self.pk_root.commit_verifier(verifier).unwrap();
        let match_var = self.pk_match.commit_verifier(verifier).unwrap();

        Ok(PublicKeyChainSecretShareVar {
            pk_root: root_var,
            pk_match: match_var.into(),
        })
    }
}

/// A public key chain share that may be linked across proofs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LinkablePublicKeyChainShareCommitment {
    /// The public root key
    pub pk_root: LinkableNonNativeElementShare,
    /// The public match key
    pub pk_match: LinkableCommitment,
}

impl From<PublicKeyChainSecretShare> for LinkablePublicKeyChainShareCommitment {
    fn from(keychain: PublicKeyChainSecretShare) -> Self {
        LinkablePublicKeyChainShareCommitment {
            pk_root: keychain.pk_root.into(),
            pk_match: keychain.pk_match.into(),
        }
    }
}

impl CommitWitness for LinkablePublicKeyChainShareCommitment {
    type VarType = PublicKeyChainSecretShareVar;
    type CommitType = PublicKeyChainSecretShareCommitment;
    type ErrorType = (); // Does not error

    fn commit_witness<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (root_var, root_comm) = self.pk_root.commit_witness(rng, prover).unwrap();
        let (match_var, match_comm) = self.pk_match.commit_witness(rng, prover).unwrap();

        Ok((
            PublicKeyChainSecretShareVar {
                pk_root: root_var,
                pk_match: match_var.into(),
            },
            PublicKeyChainSecretShareCommitment {
                pk_root: root_comm,
                pk_match: match_comm,
            },
        ))
    }
}

/// Tests for the KeyChain type
#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;
    use merlin::Transcript;
    use mpc_bulletproof::{
        r1cs::{LinearCombination, Prover},
        PedersenGens,
    };
    use num_bigint::RandBigInt;
    use rand::thread_rng;
    use rand_core::OsRng;

    use crate::{
        test_helpers::{assert_lcs_equal, random_scalar},
        types::keychain::{PublicKeyChain, PublicKeyChainSecretShareVar},
        zk_gadgets::nonnative::{NonNativeElementSecretShare, TWO_TO_256_FIELD_MOD},
        CommitPublic,
    };

    use super::PublicKeyChainSecretShare;

    #[test]
    fn test_serde() {
        let mut rng = OsRng {};
        let mut rng2 = thread_rng();

        let keychain = PublicKeyChain {
            pk_root: rng2.gen_biguint(256 /* bit_size */).into(),
            pk_match: Scalar::random(&mut rng).into(),
        };

        let serialized = serde_json::to_string(&keychain).unwrap();
        let deserialized: PublicKeyChain = serde_json::from_str(&serialized).unwrap();

        assert_eq!(keychain, deserialized);
    }

    /// Tests serialization and deserialization of keychain secret shares
    #[test]
    fn test_keychain_share_serde() {
        let n_root_words = 3;
        let keychain_share = PublicKeyChainSecretShare {
            pk_root: NonNativeElementSecretShare {
                words: (0..n_root_words).map(|_| random_scalar()).collect(),
                field_mod: TWO_TO_256_FIELD_MOD.clone(),
            },
            pk_match: random_scalar(),
        };

        // Serialize and deserialize
        let serialized: Vec<Scalar> = keychain_share.clone().into();
        let deserialized: PublicKeyChainSecretShare = serialized.into();

        assert_eq!(deserialized, keychain_share);

        // Allocate in a constraint system, then test serialization/deserialization
        let pc_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        let keychain_share_var = keychain_share.commit_public(&mut prover).unwrap();
        let serialized: Vec<LinearCombination> = keychain_share_var.clone().into();
        let deserialized: PublicKeyChainSecretShareVar = serialized.into();

        assert_eq!(
            deserialized.pk_root.words.len(),
            keychain_share_var.pk_root.words.len()
        );
        for (left, right) in deserialized
            .pk_root
            .words
            .iter()
            .zip(keychain_share_var.pk_root.words.iter())
        {
            assert_lcs_equal(left, right, &prover);
        }

        assert_lcs_equal(
            &deserialized.pk_match,
            &keychain_share_var.pk_match,
            &prover,
        );
    }
}
