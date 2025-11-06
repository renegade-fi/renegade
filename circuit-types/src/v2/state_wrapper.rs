//! A wrapper type for state elements allocated in the darkpool
//!
//! All state elements are endowed with two CSPRNGs:
//! 1. A recovery identifier CSPRNG. This stream leaks one element per update to
//!    enable off-chain indexers to track the state element's evolution on-chain
//! 2. A private share CSPRNG. This CSPRNG backs a stream cipher with which we
//!    encrypt the plaintext data
//!
//! We commit to the entire state wrapper--including the CSPRNG states--but only
//! generate ciphertext for the plaintext data in `state`

#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use itertools::Itertools;
use renegade_crypto::hash::compute_poseidon_hash;
use serde::{Deserialize, Serialize};

use std::fmt::Debug;

use crate::csprng::PoseidonCSPRNG;
use crate::traits::{BaseType, SecretShareBaseType};
use constants::Scalar;

#[cfg(feature = "proof-system-types")]
use {
    crate::traits::{CircuitBaseType, CircuitVarType},
    circuit_macros::circuit_type,
    constants::ScalarField,
    mpc_relation::{Variable, traits::Circuit},
};

/// A wrapper type for state elements allocated in the darkpool
#[cfg_attr(feature = "proof-system-types", circuit_type(serde, singleprover_circuit))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateWrapper<T>
where
    T: SecretShareBaseType + CircuitBaseType,
    T::ShareType: CircuitBaseType,
{
    /// The recovery identifier CSPRNG
    pub recovery_stream: PoseidonCSPRNG,
    /// The private share CSPRNG
    pub share_stream: PoseidonCSPRNG,
    /// The state element
    pub inner: T,
    /// The public shares of the state element
    pub public_share: T::ShareType,
}

impl<T> StateWrapper<T>
where
    T: SecretShareBaseType + CircuitBaseType,
    T::ShareType: CircuitBaseType,
{
    // --- Constructor --- //

    /// Create a new state wrapper
    ///
    /// This method will generate public shares for the element and modify the
    /// stream cipher states to do so
    pub fn new(inner: T, share_stream_seed: Scalar, recovery_stream_seed: Scalar) -> Self {
        let recovery_stream = PoseidonCSPRNG::new(recovery_stream_seed);
        let mut share_stream = PoseidonCSPRNG::new(share_stream_seed);
        let public_share = share_stream.stream_cipher_encrypt(&inner);

        Self { recovery_stream, share_stream, inner, public_share }
    }

    // --- Secret Shares --- //

    /// Compute the private shares of the state element
    pub fn private_shares(&self) -> T::ShareType {
        let val_scalars = self.inner.to_scalars();
        let public_scalars = self.public_share.to_scalars();
        let private_scalars = val_scalars
            .iter()
            .zip(public_scalars.iter())
            .map(|(val, public)| val - public)
            .collect_vec();

        T::ShareType::from_scalars(&mut private_scalars.into_iter())
    }

    /// Compute the public shares of the state element
    pub fn public_share(&self) -> T::ShareType {
        self.public_share.clone()
    }

    // --- Commitments --- //

    /// Compute a commitment to the private shares of a state element
    pub fn compute_private_commitment(&self) -> Scalar {
        // Build a list of inputs
        let num_inputs = T::NUM_SCALARS + 2 * PoseidonCSPRNG::NUM_SCALARS;
        let mut inputs = Vec::with_capacity(num_inputs);
        inputs.extend(self.private_shares().to_scalars());
        inputs.extend(self.recovery_stream.to_scalars());
        inputs.extend(self.share_stream.to_scalars());

        // Hash the inputs to commit to them
        compute_poseidon_hash(&inputs)
    }

    /// Compute a commitment to a state element given a commitment to the
    /// private shares and public shares
    pub fn compute_commitment_from_private(&self, private_commitment: Scalar) -> Scalar {
        let public_scalars = self.public_share().to_scalars();
        let mut public_comm = public_scalars[0];
        for share in public_scalars.iter().skip(1) {
            public_comm = compute_poseidon_hash(&[public_comm, *share]);
        }

        compute_poseidon_hash(&[private_commitment, public_comm])
    }

    /// Compute a commitment to a value
    pub fn compute_commitment(&self) -> Scalar {
        // Compute the commitment to the private shares then append the public shares
        let private_commitment = self.compute_private_commitment();
        self.compute_commitment_from_private(private_commitment)
    }

    // --- Nullifiers --- //

    /// Compute a nullifier for a state element
    ///
    /// The nullifier is defined as:
    ///     H(recovery_id || recovery_stream_seed)
    ///
    /// Where `recovery_id` is the recovery identifier for the current version
    /// of the element and `recovery_stream_seed` is the seed of the
    /// recovery stream. Since we need the recovery identifier of the
    /// current version, this will be the *last* index in the recovery
    /// stream.
    pub fn compute_nullifier(&self) -> Scalar {
        // Compute the last recovery identifier
        let index = self.recovery_stream.index - 1;
        let recovery_id = self.recovery_stream.get_ith(index);

        // Compute the nullifier as H(recovery_id || recovery_stream_seed)
        let recovery_stream_seed = self.recovery_stream.seed;
        compute_poseidon_hash(&[recovery_id, recovery_stream_seed])
    }

    // --- Recovery IDs --- //

    /// Compute a recovery identifier for a state element
    ///
    /// This is just the current index in the recovery stream
    ///
    /// This method mutates the recovery stream state to advance it by one
    pub fn compute_recovery_id(&mut self) -> Scalar {
        let mut csprng = self.recovery_stream.clone();
        let rid = csprng.next().unwrap();
        self.recovery_stream.index += 1;
        rid
    }

    /// Get the current recovery identifier without mutating the recovery stream
    ///
    /// Returns the recovery identifier at the current index (index - 1).
    /// This is useful when you need to read the recovery ID without advancing
    /// the stream state.
    pub fn peek_recovery_id(&self) -> Scalar {
        let index = self.recovery_stream.index;
        self.recovery_stream.get_ith(index)
    }

    // --- Stream Cipher --- //

    /// Encrypt a sequence of values using the share stream
    ///
    /// Returns the public shares (ciphertext)
    ///
    /// This method mutates the share stream state by advancing the index.
    pub fn stream_cipher_encrypt<V: SecretShareBaseType>(&mut self, value: &V) -> V::ShareType {
        self.share_stream.stream_cipher_encrypt(value)
    }

    /// Encrypt a sequence of values using the share stream
    ///
    /// Returns the public shares (ciphertext)
    ///
    /// This method does not mutate the share stream state by advancing the
    /// index.
    pub fn peek_stream_cipher_encrypt<V: SecretShareBaseType>(&self, value: &V) -> V::ShareType {
        self.share_stream.peek_stream_cipher_encrypt(value)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use constants::Scalar;
    use rand::thread_rng;

    // -----------
    // | Helpers |
    // -----------

    /// Create a dummy state wrapper
    ///
    /// For these tests the inner type is unimportant; so we use a `Scalar`
    pub fn random_state_wrapper() -> StateWrapper<Scalar> {
        let mut rng = thread_rng();
        let recovery_stream = random_csprng_state();
        let share_stream = random_csprng_state();
        let public_share = Scalar::random(&mut rng);
        StateWrapper { recovery_stream, share_stream, inner: Scalar::zero(), public_share }
    }

    /// Create a random csprng state
    pub fn random_csprng_state() -> PoseidonCSPRNG {
        let mut rng = thread_rng();
        let seed = Scalar::random(&mut rng);
        PoseidonCSPRNG::new(seed)
    }

    // ---------
    // | Tests |
    // ---------

    /// Test that peek_recovery_id returns the same value as compute_recovery_id
    /// would before mutation
    #[test]
    fn test_recovery_id_consistency() {
        let mut wrapper = random_state_wrapper();

        // Compute the recovery ID in both ways
        let peeked_id = wrapper.peek_recovery_id();
        let computed_id = wrapper.compute_recovery_id();
        assert_eq!(
            peeked_id, computed_id,
            "peek_recovery_id should return the same value as compute_recovery_id"
        );
    }
}
