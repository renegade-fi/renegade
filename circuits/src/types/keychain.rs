//! Defines the constraint system types for the set of keys a wallet holds

use std::fmt::{Formatter, Result as FmtResult};

use crypto::fields::{biguint_to_scalar, scalar_to_biguint};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use mpc_bulletproof::r1cs::{Prover, Variable, Verifier};
use num_bigint::BigUint;
use serde::{
    de::{Error as SerdeErr, SeqAccess, Visitor},
    ser::SerializeSeq,
    Deserialize, Serialize,
};

use crate::{errors::TypeConversionError, CommitProver, CommitVerifier};

/// The number of keys held in a wallet's keychain
pub const NUM_KEYS: usize = 4;

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
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct KeyChain {
    /// The public root key
    pub pk_root: Scalar,
    /// The public match key
    pub pk_match: Scalar,
    /// The public settle key
    pub pk_settle: Scalar,
    /// The public view key
    pub pk_view: Scalar,
}

/// Custom serialize/deserialize logic to serialize/deserialize as BigUint
///
/// The BigUint serialized structure is cleaner and more interpretable
impl Serialize for KeyChain {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(NUM_KEYS))?;
        seq.serialize_element(&scalar_to_biguint(&self.pk_root))?;
        seq.serialize_element(&scalar_to_biguint(&self.pk_match))?;
        seq.serialize_element(&scalar_to_biguint(&self.pk_settle))?;
        seq.serialize_element(&scalar_to_biguint(&self.pk_view))?;

        seq.end()
    }
}

impl<'de> Deserialize<'de> for KeyChain {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(KeyChainVisitor)
    }
}

/// A serde visitor implementation for the KeyChain type
struct KeyChainVisitor;
impl<'de> Visitor<'de> for KeyChainVisitor {
    type Value = KeyChain;

    fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
        write!(formatter, "a sequence of {} BigUint values", NUM_KEYS)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let pk_root: BigUint = seq
            .next_element()?
            .ok_or_else(|| SerdeErr::custom("pk_root not found in serialized value"))?;
        let pk_match: BigUint = seq
            .next_element()?
            .ok_or_else(|| SerdeErr::custom("pk_match not found in serialized value"))?;
        let pk_settle: BigUint = seq
            .next_element()?
            .ok_or_else(|| SerdeErr::custom("pk_settle not found in serialized value"))?;
        let pk_view: BigUint = seq
            .next_element()?
            .ok_or_else(|| SerdeErr::custom("pk_view not found in serialized value"))?;

        Ok(Self::Value {
            pk_root: biguint_to_scalar(&pk_root),
            pk_match: biguint_to_scalar(&pk_match),
            pk_settle: biguint_to_scalar(&pk_settle),
            pk_view: biguint_to_scalar(&pk_view),
        })
    }
}

impl TryFrom<Vec<Scalar>> for KeyChain {
    type Error = TypeConversionError;

    fn try_from(values: Vec<Scalar>) -> Result<Self, Self::Error> {
        if values.len() != NUM_KEYS {
            return Err(TypeConversionError(format!(
                "expected array of length {}, got {}",
                NUM_KEYS,
                values.len(),
            )));
        }

        Ok(Self {
            pk_root: values[0],
            pk_match: values[1],
            pk_settle: values[2],
            pk_view: values[3],
        })
    }
}

impl From<KeyChain> for Vec<Scalar> {
    fn from(keychain: KeyChain) -> Self {
        vec![
            keychain.pk_root,
            keychain.pk_match,
            keychain.pk_settle,
            keychain.pk_view,
        ]
    }
}

/// Represents a keychain that has been allocated in a single-prover constraint system
#[derive(Copy, Clone, Debug)]
pub struct KeyChainVar {
    /// The public root key
    pub pk_root: Variable,
    /// The public match key
    pub pk_match: Variable,
    /// The public settle key
    pub pk_settle: Variable,
    /// The public view key
    pub pk_view: Variable,
}

/// Represents a commitment to a keychain that has been allocated in a single-prover constraint system
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct CommittedKeyChain {
    /// The public root key
    pub pk_root: CompressedRistretto,
    /// The public match key
    pub pk_match: CompressedRistretto,
    /// The public settle key
    pub pk_settle: CompressedRistretto,
    /// The public view key
    pub pk_view: CompressedRistretto,
}

impl CommitProver for KeyChain {
    type VarType = KeyChainVar;
    type CommitType = CommittedKeyChain;
    type ErrorType = ();

    fn commit_prover<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (root_comm, root_var) = prover.commit(self.pk_root, Scalar::random(rng));
        let (match_comm, match_var) = prover.commit(self.pk_match, Scalar::random(rng));
        let (settle_comm, settle_var) = prover.commit(self.pk_settle, Scalar::random(rng));
        let (view_comm, view_var) = prover.commit(self.pk_view, Scalar::random(rng));

        Ok((
            KeyChainVar {
                pk_root: root_var,
                pk_match: match_var,
                pk_settle: settle_var,
                pk_view: view_var,
            },
            CommittedKeyChain {
                pk_root: root_comm,
                pk_match: match_comm,
                pk_settle: settle_comm,
                pk_view: view_comm,
            },
        ))
    }
}

impl CommitVerifier for CommittedKeyChain {
    type VarType = KeyChainVar;
    type ErrorType = ();

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let root_var = verifier.commit(self.pk_root);
        let match_var = verifier.commit(self.pk_match);
        let settle_var = verifier.commit(self.pk_settle);
        let view_var = verifier.commit(self.pk_view);

        Ok(KeyChainVar {
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
    use rand_core::OsRng;

    use crate::types::keychain::KeyChain;

    #[test]
    fn test_serde() {
        let mut rng = OsRng {};
        let keychain = KeyChain {
            pk_root: Scalar::random(&mut rng),
            pk_match: Scalar::random(&mut rng),
            pk_settle: Scalar::random(&mut rng),
            pk_view: Scalar::random(&mut rng),
        };

        let serialized = serde_json::to_string(&keychain).unwrap();
        let deserialized: KeyChain = serde_json::from_str(&serialized).unwrap();

        assert_eq!(keychain, deserialized);
    }
}
