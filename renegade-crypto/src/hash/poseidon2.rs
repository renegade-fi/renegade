//! Defines an implementation of the Poseidon 2 hash function: https://eprint.iacr.org/2023/323.pdf

use ark_ff::{Field, Zero};
use std::ops::MulAssign;

use crate::hash::{CAPACITY, RATE, R_F, R_P};

use super::{ScalarField, FULL_ROUND_CONSTANTS, PARTIAL_ROUND_CONSTANTS, WIDTH};

/// A sponge construction on top of the Poseidon2 permutation
#[derive(Default)]
pub struct Poseidon2Sponge {
    /// The internal state of the sponge
    pub(crate) state: [ScalarField; WIDTH],
    /// The next index in the state to absorb inputs at
    next_index: usize,
    /// Whether or not the sponge is in the squeeze state, once in squeeze state
    /// the sponge should not be reset to absorbing
    ///
    /// Note that the generic sponge construction allows such a reset, we do not
    /// support it here for simplicity
    squeezing: bool,
}

impl Poseidon2Sponge {
    /// Constructor
    pub fn new() -> Self {
        Self { state: [ScalarField::zero(); WIDTH], next_index: 0, squeezing: false }
    }

    // --------------------
    // | Sponge Interface |
    // --------------------

    /// Hash the given input and return a single-squeeze
    pub fn hash(&mut self, seq: &[ScalarField]) -> ScalarField {
        self.absorb_batch(seq);
        self.squeeze()
    }

    /// Absorb a single scalar into the sponge
    pub fn absorb(&mut self, x: &ScalarField) {
        assert!(!self.squeezing, "cannot absorb while squeezing");

        // Permute when the rate is full
        if self.next_index == RATE {
            self.permute();
            self.next_index = 0;
        }

        let entry = self.next_index + CAPACITY;
        self.state[entry] += x;
        self.next_index += 1;
    }

    /// Absorb a batch of scalars into the sponge
    pub fn absorb_batch(&mut self, x: &[ScalarField]) {
        x.iter().for_each(|x| self.absorb(x));
    }

    /// Squeeze a single scalar from the sponge
    pub fn squeeze(&mut self) -> ScalarField {
        // Once we exit the absorbing state we should permute the sponge
        // We also permute every `RATE` squeezes
        if !self.squeezing || self.next_index == RATE {
            self.permute();
            self.next_index = 0;
            self.squeezing = true;
        }

        let entry = self.next_index + CAPACITY;
        self.state[entry]
    }

    /// Squeeze a batch of scalars from the sponge
    pub fn squeeze_batch(&mut self, n: usize) -> Vec<ScalarField> {
        (0..n).map(|_| self.squeeze()).collect()
    }

    // --------------------
    // | Internal Methods |
    // --------------------

    /// Permute the inner state
    #[allow(clippy::missing_docs_in_private_items)]
    pub(crate) fn permute(&mut self) {
        // Multiply by the external round matrix
        self.external_mds();

        // Run R_F / 2 external rounds
        const HALF: usize = R_F / 2;
        for i in 0..HALF {
            self.external_round(i);
        }

        // Run all partial rounds
        for i in 0..R_P {
            self.internal_round(i);
        }

        // Run R_F / 2 external rounds
        for i in HALF..R_F {
            self.external_round(i);
        }
    }

    /// Run an external round on the state
    #[cfg_attr(feature = "inline", inline)]
    fn external_round(&mut self, round_number: usize) {
        self.external_add_rc(round_number);
        self.external_sbox();
        self.external_mds();
    }

    /// Add a round constant to the state in an external round
    #[cfg_attr(feature = "inline", inline)]
    fn external_add_rc(&mut self, round_number: usize) {
        let rc = &FULL_ROUND_CONSTANTS[round_number];
        for (state_elem, rc) in self.state.iter_mut().zip(rc.iter()) {
            *state_elem += rc;
        }
    }

    /// Apply the S-box to the entire state in an external round
    #[cfg_attr(feature = "inline", inline)]
    fn external_sbox(&mut self) {
        for state_elem in self.state.iter_mut() {
            Self::apply_sbox(state_elem);
        }
    }

    /// Apply the external MDS matrix M_E to the state
    ///
    /// For t = 3, this is the circulant matrix `circ(2, 1, 1)`
    ///
    /// This is equivalent to doubling each element then adding the other two to
    /// it, or more efficiently: adding the sum of the elements to each
    /// individual element. This efficient structure is borrowed from:
    ///     https://github.com/HorizenLabs/poseidon2/blob/main/plain_implementations/src/poseidon2/poseidon2.rs#L129-L137
    #[cfg_attr(feature = "inline", inline)]
    fn external_mds(&mut self) {
        let sum = self.state.iter().fold(ScalarField::zero(), |acc, x| acc + x);

        for state_elem in self.state.iter_mut() {
            *state_elem += sum;
        }
    }

    /// Run an internal round on the state
    ///
    /// The round number here is taken with zero being the first partial round,
    /// i.e. not offset with the full rounds that precede a set of partial
    /// rounds
    #[cfg_attr(feature = "inline", inline)]
    fn internal_round(&mut self, round_number: usize) {
        self.internal_add_rc(round_number);
        self.internal_sbox();
        self.internal_mds();
    }

    /// Add a round constant to the first state element in an internal round
    #[cfg_attr(feature = "inline", inline)]
    fn internal_add_rc(&mut self, round_number: usize) {
        let rc = &PARTIAL_ROUND_CONSTANTS[round_number];
        self.state[0] += rc;
    }

    /// Apply the S-box to the first state element in an internal round
    #[cfg_attr(feature = "inline", inline)]
    fn internal_sbox(&mut self) {
        Self::apply_sbox(&mut self.state[0]);
    }

    /// Apply the internal MDS matrix M_I to the state
    ///
    /// For t = 3, this is the matrix:
    ///     [2, 1, 1]
    ///     [1, 2, 1]
    ///     [1, 1, 3]
    ///
    /// This can be done efficiently by adding the sum to each element as in the
    /// external MDS case but adding an additional copy of the final state
    /// element
    #[cfg_attr(feature = "inline", inline)]
    fn internal_mds(&mut self) {
        let sum = self.state.iter().fold(ScalarField::zero(), |acc, x| acc + x);

        self.state[WIDTH - 1].double_in_place();
        for state_elem in self.state.iter_mut() {
            *state_elem += sum;
        }
    }

    /// Apply the s-box to an element of the state
    ///
    /// We hardcode the sbox parameterization to alpha = 5
    #[cfg_attr(feature = "inline", inline)]
    fn apply_sbox(val: &mut ScalarField) {
        let base_val = *val;

        val.square_in_place();
        val.square_in_place();
        val.mul_assign(&base_val);
    }
}

#[cfg(test)]
#[cfg(feature = "non-wasm")]
mod test {

    use ark_ff::BigInt;
    use itertools::Itertools;
    use rand::{thread_rng, Rng};
    use zkhash::{
        fields::bn256::FpBN256,
        poseidon2::{poseidon2::Poseidon2, poseidon2_instance_bn256::POSEIDON2_BN256_PARAMS},
    };

    use crate::hash::{ScalarField, RATE, WIDTH};

    use super::Poseidon2Sponge;

    /// Test the permutation against a known implementation
    #[test]
    fn test_permutation() {
        // Sample random values to permute on
        let mut rng = thread_rng();
        let values: [ScalarField; WIDTH] = rng.gen();

        let expected_hasher = Poseidon2::new(&POSEIDON2_BN256_PARAMS);
        let mut hasher = Poseidon2Sponge::new();

        // Run the expected implementation's permutation
        // We map into `BigInt` first here because although the implementations are
        // defined over the same field, the reference implementation redefines
        // the Bn254 scalar field, meaning it has a different runtime type than
        // our scalar field
        let expected_res = expected_hasher
            .permutation(&values.iter().cloned().map(BigInt::from).map(FpBN256::from).collect_vec())
            .into_iter()
            .map(BigInt::from)
            .collect_vec();

        // Run our permutation
        hasher.state = values;
        hasher.permute();

        // Compare the results
        let res = hasher.state.into_iter().map(BigInt::from).collect_vec();
        assert_eq!(expected_res, res);
    }

    /// Tests the hash by mocking a sponge with the reference
    #[test]
    fn test_hash() {
        let mut rng = thread_rng();
        let values: [ScalarField; RATE] = rng.gen();

        let expected_hasher = Poseidon2::new(&POSEIDON2_BN256_PARAMS);
        let mut hasher = Poseidon2Sponge::new();

        // Run the expected implementation, we zero prepend the input to mimic a
        // capacity buffer in a sponge
        let perm_input =
            [vec![BigInt::zero()], values.iter().cloned().map(BigInt::from).collect_vec()].concat();
        let perm_out = expected_hasher
            .permutation(&perm_input.into_iter().map(FpBN256::from).collect_vec())
            .into_iter()
            .map(BigInt::from)
            .collect_vec();

        // The first element after the `CAPACITY` buffer
        let expected_res = perm_out[1];

        // Run our hash
        let res = hasher.hash(&values);
        assert_eq!(expected_res, BigInt::from(res));
    }
}
