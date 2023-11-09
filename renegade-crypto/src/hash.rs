//! Implementations of cryptographic hash functions

mod constants;
mod poseidon2;
pub use constants::*;
pub use poseidon2::*;

#[cfg(feature = "non-wasm")]
pub use mpc_type_interface::*;

#[cfg(feature = "non-wasm")]
mod mpc_type_interface {
    //! Defines the interface for the Poseidon 2 sponge
    //!
    //! We gate this behind a feature flag to avoid importing `ark-mpc` when not
    //! necessary. This is of particular use in wasm contexts, where
    //! `ark-mpc` does not build

    use ::constants::Scalar;
    use itertools::Itertools;

    use super::Poseidon2Sponge;

    /// A hash chain from a seed used to compute CSPRNG values
    pub struct PoseidonCSPRNG {
        /// The seed of the CSPRNG, this is chained into a hash function
        /// to give pseudorandom values
        state: Scalar,
    }

    impl PoseidonCSPRNG {
        /// Constructor
        pub fn new(seed: Scalar) -> Self {
            Self { state: seed }
        }
    }

    impl Iterator for PoseidonCSPRNG {
        type Item = Scalar;

        fn next(&mut self) -> Option<Self::Item> {
            let hash_res = compute_poseidon_hash(&[self.state]);
            self.state = hash_res;

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

    /// Compute a chained Poseidon hash of the given length from the given seed
    pub fn evaluate_hash_chain(seed: Scalar, length: usize) -> Vec<Scalar> {
        let mut seed = seed.inner();
        let mut res = Vec::with_capacity(length);

        for _ in 0..length {
            // Create a new hasher to reset the internal state
            let mut hasher = Poseidon2Sponge::new();
            seed = hasher.hash(&[seed]);

            res.push(Scalar::new(seed));
        }

        res
    }
}
