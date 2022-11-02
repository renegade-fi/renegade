//! Groups gadgets that implement the Poseidon hash function
//!
//! We use the Poseidon permutation with the following parameters:
//!     \alpha = 5; i.e. the s-box is x^5 \mod p. This was chosen because:
//!     for the prime field used in Ristretto, gcd(3, p-1) = 3
//!     whereas gcd(5, p-1) = 1, making x^5 (mod p) invertible.

use num_bigint::BigUint;

use crate::constants::{POSEIDON_MDS_MATRIX_T_3, POSEIDON_ROUND_CONSTANTS_T_3};

/// The parameters for the Poseidon sponge construction
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoseidonSpongeParameters {
    /// The round constants added to the elements in between both full and partial rounds
    round_constants: Vec<Vec<BigUint>>,
    /// The MDS (maximum distance separable) matrix that is used as a mix layer
    /// i.e. after the substitution box is applied and gives \vec{x} we take MDS * \vec{x}
    mds_matrix: Vec<Vec<BigUint>>,
    /// The exponent that parameterizes the permutation; i.e. the SBox is of the form
    ///     SBox(x) = x^\alpha (mod p)
    alpha: u64,
    /// The rate at which we hash an input, i.e. t=2 for pure one-by-one sponge, and t=3 for 2-1 Merkle
    rate: usize,
    /// The number of full rounds to use in the hasher; a full round applies the SBox to each of the
    /// elements in the input, i.e. all 3 elements if we're using a rate t = 3
    full_rounds: usize,
    /// The number of partial rounds to use in the hasher; a partial round applies the SBox to only the
    /// last element of the input
    parital_rounds: usize,
}

impl PoseidonSpongeParameters {
    /// Construct a new parameter object from given parameters
    pub fn new(
        round_constants: Vec<Vec<BigUint>>,
        mds_matrix: Vec<Vec<BigUint>>,
        alpha: u64,
        rate: usize,
        full_rounds: usize,
        parital_rounds: usize,
    ) -> Self {
        // Validate inputs
        assert_eq!(
            full_rounds + parital_rounds,
            round_constants.len(),
            "must have one round constant per round"
        );
        assert!(
            mds_matrix.len() == rate && mds_matrix.iter().all(|row| row.len() == rate),
            "MDS matrix must be of size rate x rate ({:?} x {:?})",
            rate,
            rate
        );

        Self {
            round_constants,
            mds_matrix,
            alpha,
            rate,
            full_rounds,
            parital_rounds,
        }
    }
}

impl Default for PoseidonSpongeParameters {
    fn default() -> Self {
        Self {
            round_constants: POSEIDON_ROUND_CONSTANTS_T_3(),
            mds_matrix: POSEIDON_MDS_MATRIX_T_3(),
            alpha: 5,
            rate: 3,
            full_rounds: 8,
            parital_rounds: 56,
        }
    }
}

#[cfg(test)]
mod posiedon_tests {
    use super::PoseidonSpongeParameters;

    #[test]
    /// Ensure that the default parameters pass the validation checks
    fn test_params() {
        let default_params = PoseidonSpongeParameters::default();
        PoseidonSpongeParameters::new(
            default_params.round_constants,
            default_params.mds_matrix,
            default_params.alpha,
            default_params.rate,
            default_params.full_rounds,
            default_params.parital_rounds,
        );
    }
}
