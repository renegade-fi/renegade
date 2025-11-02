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
use serde::{Deserialize, Serialize};

use std::fmt::Debug;

use crate::traits::BaseType;
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
    T: CircuitBaseType,
{
    /// The recovery identifier CSPRNG
    pub recovery_stream: PoseidonCSPRNG,
    /// The private share CSPRNG
    pub share_stream: PoseidonCSPRNG,
    /// The state element
    pub inner: T,
}

impl<T> StateWrapper<T>
where
    T: CircuitBaseType,
{
    /// Compute a commitment to the private shares of a state element
    pub fn compute_private_commitment<V: crate::traits::SecretShareType>(
        &self,
        private_share: &V,
    ) -> Scalar
    where
        T: BaseType,
    {
        // Build a list of inputs
        let num_inputs = T::NUM_SCALARS + 2 * PoseidonCSPRNG::NUM_SCALARS;
        let mut inputs = Vec::with_capacity(num_inputs);
        inputs.extend(self.recovery_stream.to_scalars());
        inputs.extend(self.share_stream.to_scalars());
        inputs.extend(private_share.to_scalars());

        // Hash the inputs to commit to them
        renegade_crypto::hash::compute_poseidon_hash(&inputs)
    }

    /// Compute a commitment to a state element given a commitment to the
    /// private shares and public shares
    pub fn compute_commitment_from_private<V: crate::traits::SecretShareType>(
        private_commitment: Scalar,
        public_share: &V,
    ) -> Scalar {
        let mut comm = private_commitment;
        for share in public_share.to_scalars().iter() {
            comm = renegade_crypto::hash::compute_poseidon_hash(&[comm, *share]);
        }

        comm
    }

    /// Compute a commitment to a value
    pub fn compute_commitment<V: crate::traits::SecretShareType>(
        &self,
        private_share: &V,
        public_share: &V,
    ) -> Scalar
    where
        T: BaseType,
    {
        // Compute the commitment to the private shares then append the public shares to
        // it
        let private_commitment = self.compute_private_commitment(private_share);
        Self::compute_commitment_from_private(private_commitment, public_share)
    }

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
        renegade_crypto::hash::compute_poseidon_hash(&[recovery_id, recovery_stream_seed])
    }

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

    /// Encrypt a sequence of values using the share stream
    ///
    /// Returns the private shares (one-time pads) and the public shares
    /// (ciphertext)
    pub fn stream_cipher_encrypt<V: SecretShareType>(&mut self, value: &V::Base) -> (V, V) {
        // Generate one time pads for each value
        let value_scalars = value.to_scalars();
        let share_stream = &mut self.share_stream;
        let pads = share_stream.take(value_scalars.len()).collect_vec();

        // Advance the index after collecting the values
        let ciphertexts =
            value_scalars.iter().zip(pads.iter()).map(|(value, pad)| value - pad).collect_vec();

        // Deserialize
        let private_shares = V::from_scalars(&mut pads.into_iter());
        let public_shares = V::from_scalars(&mut ciphertexts.into_iter());
        (private_shares, public_shares)
    }
}
