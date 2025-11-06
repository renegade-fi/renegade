//! Circuit types for a CSPRNG's state

#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use itertools::Itertools;
use renegade_crypto::hash::compute_poseidon_hash;
use serde::{Deserialize, Serialize};
use std::ops::Add;

use constants::Scalar;

#[cfg(feature = "proof-system-types")]
use {
    crate::traits::{
        BaseType, CircuitBaseType, CircuitVarType, SecretShareBaseType, SecretShareType,
        SecretShareVarType,
    },
    circuit_macros::circuit_type,
    constants::ScalarField,
    mpc_relation::{Variable, traits::Circuit},
};

/// A CSPRNG's state
#[cfg_attr(feature = "proof-system-types", circuit_type(serde, singleprover_circuit, secret_share))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoseidonCSPRNG {
    /// The seed of the CSPRNG
    pub seed: Scalar,
    /// The index into the CSPRNG's stream
    pub index: u64,
}

impl Iterator for PoseidonCSPRNG {
    type Item = Scalar;

    fn next(&mut self) -> Option<Self::Item> {
        let elts = [self.seed, self.index.into()];
        let hash_res = compute_poseidon_hash(&elts);
        self.index += 1;

        Some(hash_res)
    }
}

impl PoseidonCSPRNG {
    /// Constructor
    pub fn new(seed: Scalar) -> Self {
        Self { seed, index: 0 }
    }

    /// Advance the index by the given amount
    pub fn advance_by(&mut self, amount: usize) {
        self.index += amount as u64;
    }

    /// Get the ith value in the stream without mutating the state
    ///
    /// Returns `H(seed || i)` where `H` is the Poseidon hash function
    pub fn get_ith(&self, i: u64) -> Scalar {
        let elts = [self.seed, i.into()];
        compute_poseidon_hash(&elts)
    }

    /// Encrypt a value using the CSPRNG as a stream cipher
    pub fn stream_cipher_encrypt<T: SecretShareBaseType>(&mut self, value: &T) -> T::ShareType {
        // Sample one-time pads for each value
        let value_scalars = value.to_scalars();
        let pads = self.take(value_scalars.len()).collect_vec();

        // Apply the pads to the values to get the ciphertexts
        let ciphertexts =
            value_scalars.iter().zip(pads.iter()).map(|(value, pad)| value - pad).collect_vec();
        T::ShareType::from_scalars(&mut ciphertexts.into_iter())
    }

    /// Encrypt a value using the CSPRNG as a stream cipher without mutating the
    /// state
    pub fn peek_stream_cipher_encrypt<T: SecretShareBaseType>(&self, value: &T) -> T::ShareType {
        // Sample one-time pads for each value
        let value_scalars = value.to_scalars();
        let num_values = value_scalars.len();
        let start_index = self.index;
        let mut pads = Vec::with_capacity(num_values);
        for i in start_index..start_index + num_values as u64 {
            pads.push(self.get_ith(i));
        }

        // Apply the pads to the values to get the ciphertexts
        let ciphertexts =
            value_scalars.iter().zip(pads.iter()).map(|(value, pad)| value - pad).collect_vec();
        T::ShareType::from_scalars(&mut ciphertexts.into_iter())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use constants::Scalar;
    use rand::thread_rng;

    /// Test that peek_stream_cipher_encrypt returns the same values as
    /// stream_cipher_encrypt would before mutation
    #[test]
    fn test_peek_stream_cipher_encrypt_matches_compute() {
        const N: usize = 10;
        let mut rng = thread_rng();
        let values = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();
        let values_arr = <[Scalar; N]>::from_scalars(&mut values.into_iter());

        // Compute the encryption in both ways
        let mut csprng = PoseidonCSPRNG::new(Scalar::random(&mut rng));
        let peeked_public = csprng.peek_stream_cipher_encrypt::<[Scalar; N]>(&values_arr);
        let computed_public = csprng.stream_cipher_encrypt::<[Scalar; N]>(&values_arr);

        // Check that the public shares match
        assert_eq!(
            peeked_public.to_scalars(),
            computed_public.to_scalars(),
            "peek_stream_cipher_encrypt public shares should match stream_cipher_encrypt"
        );
    }
}
