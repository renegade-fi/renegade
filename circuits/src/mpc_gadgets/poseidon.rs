//! Groups gadgets that implement the Poseidon hash function
//!
//! We use the Poseidon permutation with the following parameters:
//!     \alpha = 5; i.e. the s-box is x^5 \mod p. This was chosen because:
//!     for the prime field used in Ristretto, gcd(3, p-1) = 3
//!     whereas gcd(5, p-1) = 1, making x^5 (mod p) invertible.
//!
//! This implementation draws heavily from the Arkworks implementation for
//! security and testability against a reference implementation.
//! Their poseidon implementation can be found here:
//!     https://github.com/arkworks-rs/sponge/blob/master/src/poseidon/mod.rs

use std::cell::Ref;

use curve25519_dalek::scalar::Scalar;
use mpc_ristretto::{
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource, network::MpcNetwork,
};

use crate::{
    constants::{POSEIDON_MDS_MATRIX_T_3, POSEIDON_ROUND_CONSTANTS_T_3},
    mpc::{MpcFabric, SharedFabric},
};

/**
 * Helpers
 */

// Computes x^a using recursive doubling
fn scalar_exp<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    x: &AuthenticatedScalar<N, S>,
    a: u64,
    fabric: SharedFabric<N, S>,
) -> AuthenticatedScalar<N, S> {
    if a == 0 {
        fabric.borrow_fabric().allocate_public_u64(1 /* value */)
    } else if a == 1 {
        x.clone()
    } else if a % 2 == 1 {
        let recursive_result = scalar_exp(x, (a - 1) / 2, fabric);
        &recursive_result * &recursive_result * x
    } else {
        let recursive_result = scalar_exp(x, a / 2, fabric);
        &recursive_result * &recursive_result
    }
}

/// The parameters for the Poseidon sponge construction
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoseidonSpongeParameters {
    /// The round constants added to the elements in between both full and partial rounds
    pub round_constants: Vec<Vec<Scalar>>,
    /// The MDS (maximum distance separable) matrix that is used as a mix layer
    /// i.e. after the substitution box is applied and gives \vec{x} we take MDS * \vec{x}
    pub mds_matrix: Vec<Vec<Scalar>>,
    /// The exponent that parameterizes the permutation; i.e. the SBox is of the form
    ///     SBox(x) = x^\alpha (mod p)
    pub alpha: u64,
    /// The rate at which we hash an input, i.e. the number of field elements the sponge can
    /// absorb in between permutations
    pub rate: usize,
    /// The security capacity of the sponge, the width of the state that is neither absorbed
    /// into, nor squeezed from
    pub capacity: usize,
    /// The number of full rounds to use in the hasher; a full round applies the SBox to each of the
    /// elements in the input, i.e. all 3 elements if we're using a rate t = 3
    pub full_rounds: usize,
    /// The number of partial rounds to use in the hasher; a partial round applies the SBox to only the
    /// last element of the input
    pub parital_rounds: usize,
}

impl PoseidonSpongeParameters {
    /// Construct a new parameter object from given parameters
    pub fn new(
        round_constants: Vec<Vec<Scalar>>,
        mds_matrix: Vec<Vec<Scalar>>,
        alpha: u64,
        rate: usize,
        capacity: usize,
        full_rounds: usize,
        parital_rounds: usize,
    ) -> Self {
        // Validate inputs
        let state_width = rate + capacity;
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
            round_constants.iter().all(|rc| rc.len() == state_width),
            "round constants must be the same width as the state"
        );
        assert!(
            mds_matrix.len() == state_width
                && mds_matrix.iter().all(|row| row.len() == state_width),
            "MDS matrix must be of size rate x rate ({:?} x {:?})",
            state_width,
            state_width
        );

        Self {
            round_constants,
            mds_matrix,
            alpha,
            rate,
            capacity,
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
            rate: 2,
            capacity: 1,
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
pub struct AuthenticatedPoseidonHasher<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The parameterization of the hash function
    params: PoseidonSpongeParameters,
    /// The hash state
    state: Vec<AuthenticatedScalar<N, S>>,
    /// The next index in the state to being absorbing inputs at
    next_index: usize,
    /// Whether the sponge is in squeezing mode. For simplicity, we disallow
    /// the case in which a caller wishes to squeeze values and the absorb more.
    in_squeeze_state: bool,
    /// A reference to the shared MPC fabric that the computation variables are allocated in
    fabric: SharedFabric<N, S>,
}

/// Native implementation, can be done outside the context of a constraint system
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> AuthenticatedPoseidonHasher<N, S> {
    /// Construct a new sponge hasher
    /// TODO: Ideally we don't pass in the fabric here, this makes the gadget non-general between
    /// AuthenticatedScalar and Scalar
    pub fn new(params: &PoseidonSpongeParameters, fabric: SharedFabric<N, S>) -> Self {
        let inital_state = fabric
            .borrow_fabric()
            .allocate_zeros(params.rate + params.capacity);
        Self {
            params: params.clone(),
            state: inital_state,
            next_index: 0,
            in_squeeze_state: false, // Start in absorb state
            fabric,
        }
    }

    /// Borrow a reference to the shared fabric
    fn borrow_fabric(&self) -> Ref<MpcFabric<N, S>> {
        self.fabric.borrow_fabric()
    }

    /// Absorb an input into the hasher state
    ///
    /// Here, we match the arkworks sponge implementation (link below) in that we absorb
    /// until we have added one element to each element of the state; and only then do we permute.
    /// Put differently, we wait to absorb `rate` elements between permutations.
    ///
    /// When squeezing, we must make sure that a permutation *does* happen in the case that
    /// the `rate`-sized state was never filled. See the implementation below.
    ///
    /// Arkworks sponge poseidon: https://github.com/arkworks-rs/sponge/blob/master/src/poseidon/mod.rs
    pub fn absorb(&mut self, a: &AuthenticatedScalar<N, S>) {
        assert!(
            !self.in_squeeze_state,
            "Cannot absorb from a sponge that has already been squeezed"
        );

        // Permute the digest state if we have filled up the `rate`-sized buffer
        if self.next_index == self.params.rate {
            self.permute();
            self.next_index = 0;
        }

        self.state[self.params.capacity + self.next_index] += a;
        self.next_index += 1;
    }

    /// Absorb a batch of scalars into the hasher
    pub fn absorb_batch(&mut self, a: &[AuthenticatedScalar<N, S>]) {
        a.iter().for_each(|val| self.absorb(val));
    }

    /// Squeeze an output from the hasher state
    ///
    /// A similar approach is taken here to the one in `absorb`. Specifically, we allow this method
    /// to be called `rate` times in between permutations, to exhaust the state buffer.    pub fn squeeze(&mut self) -> Scalar {
    pub fn squeeze(&mut self) -> AuthenticatedScalar<N, S> {
        // Once we exit the absorb state, ensure that the digest state is permuted before squeezing
        if !self.in_squeeze_state || self.next_index == self.params.rate {
            self.permute();
            self.next_index = 0;
            self.in_squeeze_state = true;
        }
        self.next_index += 1;
        self.state[self.params.capacity + self.next_index - 1].clone()
    }

    /// Squeeze a batch of outputs from the hasher
    pub fn squeeze_batch(&mut self, num_elements: usize) -> Vec<AuthenticatedScalar<N, S>> {
        (0..num_elements).map(|_| self.squeeze()).collect()
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
        let final_full_rounds_end = self.params.parital_rounds + self.params.full_rounds;
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
                *elem = scalar_exp(elem, self.params.alpha, self.fabric.clone());
            }
        } else {
            self.state[0] = scalar_exp(&self.state[0], self.params.alpha, self.fabric.clone())
        }
    }

    /// Apply the MDS matrix to the state
    /// TODO: Optimize this as well
    fn apply_mds(&mut self) {
        let mut res = Vec::with_capacity(self.params.rate);
        for row in self.params.mds_matrix.iter() {
            let mut row_inner_product = self.borrow_fabric().allocate_zero();
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
    use ark_sponge::{poseidon::PoseidonSponge, CryptographicSponge};
    use integration_helpers::mpc_network::mock_mpc_fabric;
    use rand::{thread_rng, Rng, RngCore};

    use crate::{
        mpc::SharedFabric,
        test_helpers::{compare_scalar_to_felt, convert_params, TestField},
    };

    use super::{AuthenticatedPoseidonHasher, PoseidonSpongeParameters};

    /// Ensure that the default parameters pass the validation checks
    #[test]
    fn test_params() {
        let default_params = PoseidonSpongeParameters::default();
        PoseidonSpongeParameters::new(
            default_params.round_constants,
            default_params.mds_matrix,
            default_params.alpha,
            default_params.rate,
            default_params.capacity,
            default_params.full_rounds,
            default_params.parital_rounds,
        );
    }

    /// Tests the input against the Arkworks implementation of the Poseidon hash
    #[test]
    fn test_against_arkworks() {
        let native_parameters = PoseidonSpongeParameters::default();
        let arkworks_params = convert_params(&native_parameters);

        // Generate a random number of random elements
        let mut rng = thread_rng();
        let n = rng.gen_range(1..101);
        let mut random_vec = Vec::with_capacity(n);
        for _ in 0..n {
            random_vec.push(rng.next_u64());
        }

        // Hash and squeeze with arkworks first
        let mut arkworks_poseidon = PoseidonSponge::new(&arkworks_params);
        for random_elem in random_vec.iter() {
            // Arkworks Fp256 does not implement From<u64> so we have to
            // cast to i128 first to ensure that the value is not represented as a negative
            arkworks_poseidon.absorb(&TestField::from(*random_elem as i128));
        }

        let arkworks_squeezed: TestField =
            arkworks_poseidon.squeeze_field_elements(1 /* num_elements */)[0];

        // Hash and squeeze in native hasher
        let mock_fabric = mock_mpc_fabric(0 /* party_id */);
        let mut native_poseidon =
            AuthenticatedPoseidonHasher::new(&native_parameters, SharedFabric(mock_fabric.clone()));
        for random_elem in random_vec.iter() {
            native_poseidon.absorb(
                &mock_fabric
                    .as_ref()
                    .borrow()
                    .allocate_public_u64(*random_elem),
            )
        }

        let native_squeezed = native_poseidon.squeeze().to_scalar();
        assert!(compare_scalar_to_felt(&native_squeezed, &arkworks_squeezed));
    }
}
