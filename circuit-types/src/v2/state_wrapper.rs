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

use crate::traits::{BaseType, SecretShareBaseType};
use crate::{csprng::PoseidonCSPRNG, traits::SecretShareType};
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
    /// Returns the private shares (one-time pads) and the public shares
    /// (ciphertext)
    ///
    /// This method mutates the share stream state by advancing the index.
    pub fn stream_cipher_encrypt<V: SecretShareType>(&mut self, value: &V::Base) -> V {
        // Generate one time pads for each value
        let value_scalars = value.to_scalars();
        let share_stream = &mut self.share_stream;
        let pads = share_stream.take(value_scalars.len()).collect_vec();

        // Advance the index after collecting the values
        let ciphertexts =
            value_scalars.iter().zip(pads.iter()).map(|(value, pad)| value - pad).collect_vec();

        // Deserialize
        V::from_scalars(&mut ciphertexts.into_iter())
    }

    /// Encrypt a sequence of values using the share stream without mutating the
    /// stream state
    ///
    /// Returns the private shares (one-time pads) and the public shares
    /// (ciphertext) that would be generated from the current stream position.
    ///
    /// This method does not mutate the share stream state; it is useful for
    /// for peeking at what the encryption would produce without advancing the
    /// stream.
    pub fn peek_stream_cipher_encrypt<V: SecretShareType>(&self, value: &V::Base) -> V {
        // Generate one time pads for each value using get_ith without mutating
        let value_scalars = value.to_scalars();
        let start_index = self.share_stream.index;
        let pads: Vec<Scalar> = (0..value_scalars.len())
            .map(|i| self.share_stream.get_ith(start_index + i as u64))
            .collect_vec();

        // Compute ciphertexts
        let ciphertexts =
            value_scalars.iter().zip(pads.iter()).map(|(value, pad)| value - pad).collect_vec();

        // Deserialize
        V::from_scalars(&mut ciphertexts.into_iter())
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

    /// Test that peek_stream_cipher_encrypt returns the same values as
    /// stream_cipher_encrypt would before mutation
    #[test]
    fn test_peek_stream_cipher_encrypt_matches_compute() {
        const N: usize = 10;
        let mut rng = thread_rng();
        let values = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();
        let values_arr = <[Scalar; N]>::from_scalars(&mut values.into_iter());

        // Compute the encryption in both ways
        let mut wrapper = random_state_wrapper();
        let peeked_public = wrapper.peek_stream_cipher_encrypt::<[Scalar; N]>(&values_arr);
        let computed_public = wrapper.stream_cipher_encrypt::<[Scalar; N]>(&values_arr);

        // Check that the public shares match
        assert_eq!(
            peeked_public.to_scalars(),
            computed_public.to_scalars(),
            "peek_stream_cipher_encrypt public shares should match stream_cipher_encrypt"
        );
    }
}
