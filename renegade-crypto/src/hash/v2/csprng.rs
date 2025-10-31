//! CSPRNG implementation using Poseidon 2 hash function
//!
//! We gate this behind a feature flag to avoid importing `ark-mpc` when not
//! necessary. This is of particular use in wasm contexts, where
//! `ark-mpc` does not build

use ::constants::Scalar;
use itertools::Itertools;

use crate::hash::Poseidon2Sponge;

/// A hash chain from a seed used to compute CSPRNG values
pub struct PoseidonCSPRNG {
    /// The index of the next element to generate
    index: usize,
    /// The seed of the CSPRNG; the ith element is defined as H(seed || i)
    seed: Scalar,
}

impl PoseidonCSPRNG {
    /// Constructor
    pub fn new(seed: Scalar) -> Self {
        Self { index: 0, seed }
    }

    /// Advance the index by the given amount
    pub fn advance_by(&mut self, amount: usize) {
        self.index += amount;
    }
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

/// Compute the hash of the randomness of a given wallet
pub fn compute_poseidon_hash(values: &[Scalar]) -> Scalar {
    let input_seq = values.iter().map(Scalar::inner).collect_vec();
    let mut hasher = Poseidon2Sponge::new();
    let res = hasher.hash(&input_seq);

    Scalar::new(res)
}

#[cfg(test)]
mod test {
    use rand::{Rng, thread_rng};

    use super::*;

    /// Test the CSPRNG
    #[test]
    fn test_csprng() {
        let mut rng = thread_rng();
        let seed = Scalar::random(&mut rng);
        let mut csprng = PoseidonCSPRNG::new(seed);

        // Check the first element
        let next = csprng.next().unwrap();
        let expected = compute_poseidon_hash(&[seed, Scalar::zero()]);
        assert_eq!(next, expected);

        // Check a random element
        let random_idx: u64 = rng.r#gen();
        csprng.advance_by((random_idx - 1) as usize);
        let next = csprng.next().unwrap();
        let expected = compute_poseidon_hash(&[seed, random_idx.into()]);
        assert_eq!(next, expected);
    }
}
