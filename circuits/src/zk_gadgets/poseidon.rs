//! Groups gadgets that implement the Poseidon hash function
//!
//! We use the Poseidon permutation with the following parameters:
//!     \alpha = 5; i.e. the s-box is x^5 \mod p. This was chosen because:
//!     for the prime field used in Ristretto, gcd(3, p-1) = 3
//!     whereas gcd(5, p-1) = 1, making x^5 (mod p) invertible.

use curve25519_dalek::scalar::Scalar;

use crate::constants::{POSEIDON_MDS_MATRIX_T_3, POSEIDON_ROUND_CONSTANTS_T_3};

/**
 * Helpers
 */

// Computes x^a using recursive doubling
fn scalar_exp(x: Scalar, a: u64) -> Scalar {
    if a == 0 {
        Scalar::one()
    } else if a == 1 {
        x
    } else if a % 2 == 1 {
        let recursive_result = scalar_exp(x, (a - 1) / 2);
        recursive_result * recursive_result * x
    } else {
        let recursive_result = scalar_exp(x, a / 2);
        recursive_result * recursive_result
    }
}

/// The parameters for the Poseidon sponge construction
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoseidonSpongeParameters {
    /// The round constants added to the elements in between both full and partial rounds
    round_constants: Vec<Vec<Scalar>>,
    /// The MDS (maximum distance separable) matrix that is used as a mix layer
    /// i.e. after the substitution box is applied and gives \vec{x} we take MDS * \vec{x}
    mds_matrix: Vec<Vec<Scalar>>,
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
        round_constants: Vec<Vec<Scalar>>,
        mds_matrix: Vec<Vec<Scalar>>,
        alpha: u64,
        rate: usize,
        full_rounds: usize,
        parital_rounds: usize,
    ) -> Self {
        // Validate inputs
        assert_eq!(
            full_rounds % 2,
            0,
            "The number of full rounds must be divisible by two"
        );
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

    /// Fetch the round constants for a given round
    pub fn get_round_constant(&self, round_index: usize) -> &Vec<Scalar> {
        &self.round_constants[round_index]
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

/// A gadget that implements the Poseidon hash function:
///     https://eprint.iacr.org/2019/458.pdf
///
/// TODO: This should ideally work for both AuthenticatedScalars and Scalars
#[derive(Clone, Debug)]
pub struct PoseidonHashGadget {
    /// The parameterization of the hash function
    params: PoseidonSpongeParameters,
    /// The hash state
    state: Vec<Scalar>,
}

impl PoseidonHashGadget {
    /// Construct a new sponge hasher
    /// TODO: Ideally we don't pass in the fabric here, this makes the gadget non-general between
    /// AuthenticatedScalar and Scalar
    pub fn new(params: PoseidonSpongeParameters) -> Self {
        let inital_state = vec![Scalar::zero(); params.rate];
        Self {
            params,
            state: inital_state,
        }
    }
    /// Absorb an input into the hasher state
    pub fn absorb(&mut self, a: &[Scalar]) {
        assert_eq!(
            a.len(),
            self.params.rate,
            "Expected input of width {:?}, got {:?}",
            self.params.rate,
            a.len()
        );

        // Permute on the input
        for (state_elem, input) in self.state.iter_mut().zip(a.iter()) {
            *state_elem += input
        }
        self.permute();
    }

    /// Squeeze an element out of the hasher
    pub fn squeeze(&mut self) -> Scalar {
        self.permute();
        self.state[0]
    }

    /// Run the Poseidon permutation function
    fn permute(&mut self) {
        // Compute full_rounds / 2 rounds in which the sbox is applied to all elements
        for round in 0..self.params.full_rounds / 2 {
            self.add_round_constants(round);
            self.apply_sbox(true /* full_round */);
            self.apply_mds();
        }

        // Compute partial_rounds rounds in which the sbox is applied to only the last element
        let partial_rounds_start = self.params.full_rounds / 2;
        let partial_rounds_end = partial_rounds_start + self.params.parital_rounds;
        for round in partial_rounds_start..partial_rounds_end {
            self.add_round_constants(round);
            self.apply_sbox(false /* full_round */);
            self.apply_mds();
        }

        // Compute another full_rounds / 2 rounds in which we apply the sbox to all elements
        let final_full_rounds_start = partial_rounds_end;
        let final_full_rounds_end = partial_rounds_end + self.params.full_rounds / 2;
        for round in final_full_rounds_start..final_full_rounds_end {
            self.add_round_constants(round);
            self.apply_sbox(true /* full_round */);
            self.apply_mds();
        }
    }

    /// Add the next round constants to the state
    fn add_round_constants(&mut self, round_index: usize) {
        for (elem, round_constant) in self
            .state
            .iter_mut()
            .zip(self.params.get_round_constant(round_index))
        {
            *elem += *round_constant
        }
    }

    /// Apply the sbox to the state
    /// TODO: Optimize this
    fn apply_sbox(&mut self, full_round: bool) {
        // If this is a full round, apply the sbox to each elem
        if full_round {
            for elem in self.state.iter_mut() {
                *elem = scalar_exp(*elem, self.params.alpha);
            }
        }
    }

    /// Apply the MDS matrix to the state
    /// TODO: Optimize this as well
    fn apply_mds(&mut self) {
        let mut res = Vec::with_capacity(self.params.rate);
        for row in self.params.mds_matrix.iter() {
            let mut row_inner_product = Scalar::zero();
            for (a, b) in row.iter().zip(self.state.iter()) {
                row_inner_product += a * b;
            }

            res.push(row_inner_product);
        }

        // Update the state directly
        for (old_state_elem, new_state_elem) in self.state.iter_mut().zip(res.into_iter()) {
            *old_state_elem = new_state_elem;
        }
    }
}

#[cfg(test)]
mod posiedon_tests {
    use curve25519_dalek::scalar::Scalar;
    use rand_core::OsRng;

    use crate::scalar_to_bigint;

    use super::{PoseidonHashGadget, PoseidonSpongeParameters};

    /// Ensure that the default parameters pass the validation checks
    #[test]
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

    /// Tests that the poseidon hash returns as expected
    /// TODO: Correctness
    #[test]
    fn test_absorb_and_squeeze() {
        let default_params = PoseidonSpongeParameters::default();
        let mut hasher = PoseidonHashGadget::new(default_params);

        // Generate 15 random elements, will be absorbed in groups of 3
        let n = 15;
        let mut rng = OsRng {};
        let mut random_vec = Vec::with_capacity(n);
        for _ in 0..n {
            random_vec.push(Scalar::random(&mut rng));
        }

        // Hash the random elements
        for i in (0..n).step_by(3) {
            hasher.absorb(&[random_vec[i], random_vec[i + 1], random_vec[i + 2]]);
        }

        let squeezed = scalar_to_bigint(&hasher.squeeze());
        println!("Hash out: {:?}", squeezed);
    }
}
