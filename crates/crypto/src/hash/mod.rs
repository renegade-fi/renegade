//! Implementations of cryptographic hash functions

mod constants;
mod poseidon2;
pub use constants::*;
pub use poseidon2::*;

use ::constants::Scalar;
use itertools::Itertools;

/// Compute the hash of the randomness of a given wallet
pub fn compute_poseidon_hash(values: &[Scalar]) -> Scalar {
    let input_seq = values.iter().map(Scalar::inner).collect_vec();
    let mut hasher = Poseidon2Sponge::new();
    let res = hasher.hash(&input_seq);

    Scalar::new(res)
}
