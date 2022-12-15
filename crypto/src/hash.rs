//! Implementations of cryptographic hash functions

use ark_sponge::{
    poseidon::{PoseidonConfig, PoseidonSponge},
    CryptographicSponge,
};
use itertools::Itertools;

use crate::{
    constants::{POSEIDON_MDS_MATRIX_T_3, POSEIDON_ROUND_CONSTANTS_T_3},
    fields::DalekRistrettoField,
};

/// Hash the input using a Poseidon hash with default parameters
///
/// Uses defaults from the `circuits` package to ensure that hashes are
/// consistent with those produced by the proof system
///
/// We require that the input be castable to a vector of u64s; this is to
/// match the hashes defined in the ZK circuitry
pub fn poseidon_hash_default_params<T: Into<Vec<u64>>>(val: T) -> DalekRistrettoField {
    let hashable_values: Vec<u64> = val.into();
    let arkworks_input = hashable_values
        .into_iter()
        .map(DalekRistrettoField::from)
        .collect_vec();

    let mut arkworks_hasher = PoseidonSponge::new(&default_poseidon_params());
    for val in arkworks_input.iter() {
        arkworks_hasher.absorb(val)
    }

    arkworks_hasher.squeeze_field_elements(1 /* num_elements */)[0]
}

/// Returns a default set of arkworks params
///
/// We use the Poseidon permutation with the following default parameters:
///     \alpha = 5; i.e. the s-box is x^5 \mod p. This was chosen because:
///     for the prime field used in Ristretto, gcd(3, p-1) = 3
///     whereas gcd(5, p-1) = 1, making x^5 (mod p) invertible.
pub fn default_poseidon_params() -> PoseidonConfig<DalekRistrettoField> {
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
