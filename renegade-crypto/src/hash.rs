//! Implementations of cryptographic hash functions

use ark_crypto_primitives::sponge::{
    poseidon::{PoseidonConfig, PoseidonSponge},
    CryptographicSponge,
};
use itertools::Itertools;
use mpc_stark::algebra::scalar::Scalar;

use crate::constants::{POSEIDON_MDS_MATRIX_T_3, POSEIDON_ROUND_CONSTANTS_T_3};

/// A type alias for the arkworks Poseidon sponge over the Stark field
pub type PoseidonParams = PoseidonConfig<Scalar::Field>;

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

/// Hash the input using a Poseidon hash with default parameters
///
/// Uses defaults from the `circuits` package to ensure that hashes are
/// consistent with those produced by the proof system
///
/// We require that the input be castable to a vector of u64s; this is to
/// match the hashes defined in the ZK circuitry
pub fn poseidon_hash_default_params<T: Into<Scalar>>(val: Vec<T>) -> Scalar {
    let input = val.into_iter().map(|x| x.into().inner()).collect_vec();
    let mut arkworks_hasher = PoseidonSponge::new(&default_poseidon_params());
    for val in input.into_iter() {
        arkworks_hasher.absorb(&val)
    }

    let out: Scalar::Field = arkworks_hasher.squeeze_field_elements(1 /* num_elements */)[0];
    out.into()
}

/// Compute the hash of the randomness of a given wallet
pub fn compute_poseidon_hash(values: &[Scalar]) -> Scalar {
    poseidon_hash_default_params(values.to_vec())
}

/// Returns a default set of arkworks params
///
/// We use the Poseidon permutation with the following default parameters:
///     \alpha = 5; i.e. the s-box is x^5 \mod p. This was chosen because:
///     for the prime field used in Stark curve Scalar field, gcd(3, p-1) = 3
///     whereas gcd(5, p-1) = 1, making x^5 (mod p) invertible.
pub fn default_poseidon_params() -> PoseidonConfig<Scalar::Field> {
    PoseidonConfig::new(
        8,                              /* full_rounds */
        56,                             /* partial_rounds */
        5,                              /* alpha */
        POSEIDON_MDS_MATRIX_T_3(),      /* mds matrix */
        POSEIDON_ROUND_CONSTANTS_T_3(), /* round constants */
        2,                              /* rate */
        1,                              /* capacity */
    )
}

/// Compute a chained Poseidon hash of the given length from the given seed
pub fn evaluate_hash_chain(seed: Scalar, length: usize) -> Vec<Scalar> {
    let mut seed = seed.inner();
    let mut res = Vec::with_capacity(length);

    let poseidon_config = default_poseidon_params();
    for _ in 0..length {
        // New hasher every time to reset the hash state, Arkworks sponges don't natively
        // support resets, so we pay the small re-initialization overhead
        let mut hasher = PoseidonSponge::new(&poseidon_config);
        hasher.absorb(&seed);
        seed = hasher.squeeze_field_elements(1 /* num_elements */)[0];

        res.push(Scalar::from(seed));
    }

    res
}
