//! Groups gadgets that implement the Poseidon hash function
//!
//! We use the Poseidon permutation with the following parameters:
//!     \alpha = 5; i.e. the s-box is x^5 \mod p. This was chosen because:
//!     for the prime field used in the Stark curve, gcd(3, p-1) = 3
//!     whereas gcd(5, p-1) = 1, making x^5 (mod p) invertible.
//!
//! This implementation draws heavily from the Arkworks implementation for
//! security and testability against a reference implementation.
//! Their poseidon implementation can be found here:
//!     https://github.com/arkworks-rs/sponge/blob/master/src/poseidon/mod.rs

use mpc_stark::{
    algebra::{authenticated_scalar::AuthenticatedScalarResult, scalar::Scalar},
    MpcFabric,
};
use renegade_crypto::hash::PoseidonParams;

// -----------
// | Helpers |
// -----------

/// Computes x^a using recursive doubling
fn scalar_exp(
    x: &AuthenticatedScalarResult,
    a: u64,
    fabric: &MpcFabric,
) -> AuthenticatedScalarResult {
    if a == 0 {
        fabric.one_authenticated()
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

/// A gadget that implements the Poseidon hash function:
///     https://eprint.iacr.org/2019/458.pdf
///
/// TODO: This should ideally work for both AuthenticatedScalars and Scalars
#[derive(Clone, Debug)]
pub struct AuthenticatedPoseidonHasher {
    /// The parameterization of the hash function
    params: PoseidonParams,
    /// The hash state
    state: Vec<AuthenticatedScalarResult>,
    /// The next index in the state to being absorbing inputs at
    next_index: usize,
    /// Whether the sponge is in squeezing mode. For simplicity, we disallow
    /// the case in which a caller wishes to squeeze values and the absorb more.
    in_squeeze_state: bool,
    /// A reference to the shared MPC fabric that the computation variables are
    /// allocated in
    fabric: MpcFabric,
}

/// Native implementation, can be done outside the context of a constraint
/// system
impl AuthenticatedPoseidonHasher {
    /// Construct a new sponge hasher
    /// TODO: Ideally we don't pass in the fabric here, this makes the gadget
    /// non-general between AuthenticatedScalar and Scalar
    pub fn new(params: &PoseidonParams, fabric: MpcFabric) -> Self {
        let initial_state = fabric.zeros_authenticated(params.rate + params.capacity);
        Self {
            params: params.clone(),
            state: initial_state,
            next_index: 0,
            in_squeeze_state: false, // Start in absorb state
            fabric,
        }
    }

    /// Absorb an input into the hasher state
    ///
    /// Here, we match the arkworks sponge implementation (link below) in that
    /// we absorb until we have added one element to each element of the
    /// state; and only then do we permute. Put differently, we wait to
    /// absorb `rate` elements between permutations.
    ///
    /// When squeezing, we must make sure that a permutation *does* happen in
    /// the case that the `rate`-sized state was never filled. See the
    /// implementation below.
    ///
    /// Arkworks sponge poseidon: https://github.com/arkworks-rs/sponge/blob/master/src/poseidon/mod.rs
    pub fn absorb(&mut self, a: &AuthenticatedScalarResult) {
        assert!(
            !self.in_squeeze_state,
            "Cannot absorb from a sponge that has already been squeezed"
        );

        // Permute the digest state if we have filled up the `rate`-sized buffer
        if self.next_index == self.params.rate {
            self.permute();
            self.next_index = 0;
        }

        self.state[self.params.capacity + self.next_index] =
            &self.state[self.params.capacity + self.next_index] + a;
        self.next_index += 1;
    }

    /// Absorb a batch of scalars into the hasher
    pub fn absorb_batch(&mut self, a: &[AuthenticatedScalarResult]) {
        a.iter().for_each(|val| self.absorb(val));
    }

    /// Squeeze an output from the hasher state
    ///
    /// A similar approach is taken here to the one in `absorb`. Specifically,
    /// we allow this method to be called `rate` times in between
    /// permutations, to exhaust the state buffer.    pub fn squeeze(&mut self)
    /// -> Scalar {
    pub fn squeeze(&mut self) -> AuthenticatedScalarResult {
        // Once we exit the absorb state, ensure that the digest state is permuted
        // before squeezing
        if !self.in_squeeze_state || self.next_index == self.params.rate {
            self.permute();
            self.next_index = 0;
            self.in_squeeze_state = true;
        }
        self.next_index += 1;
        self.state[self.params.capacity + self.next_index - 1].clone()
    }

    /// Squeeze a batch of outputs from the hasher
    pub fn squeeze_batch(&mut self, num_elements: usize) -> Vec<AuthenticatedScalarResult> {
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

        // Compute partial_rounds rounds in which the sbox is applied to only the last
        // element
        let partial_rounds_start = self.params.full_rounds / 2;
        let partial_rounds_end = partial_rounds_start + self.params.partial_rounds;
        for round in partial_rounds_start..partial_rounds_end {
            self.add_round_constants(round);
            self.apply_sbox(false /* full_round */);
            self.apply_mds();
        }

        // Compute another full_rounds / 2 rounds in which we apply the sbox to all
        // elements
        let final_full_rounds_start = partial_rounds_end;
        let final_full_rounds_end = self.params.partial_rounds + self.params.full_rounds;
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
            .zip(self.params.ark[round_index].iter())
        {
            *elem = &*elem + Scalar::from(*round_constant)
        }
    }

    /// Apply the sbox to the state
    /// TODO: Optimize this
    fn apply_sbox(&mut self, full_round: bool) {
        // If this is a full round, apply the sbox to each elem
        if full_round {
            for elem in self.state.iter_mut() {
                *elem = scalar_exp(elem, self.params.alpha, &self.fabric);
            }
        } else {
            self.state[0] = scalar_exp(&self.state[0], self.params.alpha, &self.fabric)
        }
    }

    /// Apply the MDS matrix to the state
    /// TODO: Optimize this as well
    fn apply_mds(&mut self) {
        let mut res = Vec::with_capacity(self.params.rate);
        for row in self.params.mds.iter() {
            let mut row_inner_product = self.fabric.zero_authenticated();
            for (a, b) in row.iter().zip(self.state.iter()) {
                row_inner_product = row_inner_product + b * Scalar::from(*a);
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
mod poseidon_tests {
    use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
    use itertools::Itertools;
    use mpc_stark::{algebra::scalar::Scalar, PARTY0};
    use rand::{thread_rng, Rng, RngCore};
    use renegade_crypto::hash::default_poseidon_params;
    use test_helpers::mpc_network::execute_mock_mpc;

    use super::AuthenticatedPoseidonHasher;

    /// Tests the input against the Arkworks implementation of the Poseidon hash
    #[tokio::test]
    async fn test_against_arkworks() {
        let params = default_poseidon_params();

        // Generate a random number of random elements
        let mut rng = thread_rng();
        let n = rng.gen_range(1..101);
        let mut random_vec = Vec::with_capacity(n);
        for _ in 0..n {
            random_vec.push(rng.next_u64());
        }

        // Hash and squeeze with arkworks first
        let mut arkworks_poseidon = PoseidonSponge::new(&params);
        for random_elem in random_vec.iter() {
            // Arkworks Fp256 does not implement From<u64> so we have to
            // cast to i128 first to ensure that the value is not represented as a negative
            arkworks_poseidon.absorb(&Scalar::Field::from(*random_elem as i128));
        }

        let arkworks_squeezed: Scalar::Field =
            arkworks_poseidon.squeeze_field_elements(1 /* num_elements */)[0];

        // Hash and squeeze in an MPC circuit
        let (party0_res, _) = execute_mock_mpc(move |fabric| {
            let params = params.clone();
            let random_vec = random_vec.clone();

            async move {
                let mut poseidon = AuthenticatedPoseidonHasher::new(&params, fabric.clone());
                let allocated_elems = random_vec
                    .into_iter()
                    .map(|elem| fabric.share_scalar(elem, PARTY0))
                    .collect_vec();

                for random_elem in allocated_elems.into_iter() {
                    poseidon.absorb(&random_elem)
                }

                poseidon.squeeze().open().await
            }
        })
        .await;

        assert_eq!(party0_res, Scalar::from(arkworks_squeezed));
    }
}
