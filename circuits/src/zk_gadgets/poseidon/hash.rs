//! Groups logic for adding Poseidon hash function constraints to a Bulletproof
//! constraint system

use ark_ff::{One, Zero};
use constants::ScalarField;
use itertools::Itertools;
use mpc_relation::{Variable, errors::CircuitError, traits::Circuit};
use renegade_crypto::hash::{
    CAPACITY, FULL_ROUND_CONSTANTS, PARTIAL_ROUND_CONSTANTS, R_F, R_P, RATE,
};

use super::gates::{FusedExternalSboxMDSGate, FusedInternalSboxMDSGate};

// -----------------
// | CSPRNG Gadget |
// -----------------

/// A gadget for sampling a Poseidon sponge as a CSPRNG
pub struct PoseidonCSPRNGGadget;
impl PoseidonCSPRNGGadget {
    /// Samples values from a chained Poseidon hash CSPRNG, seeded with the
    /// given input
    pub fn sample<C: Circuit<ScalarField>>(
        mut seed: Variable,
        num_vals: usize,
        cs: &mut C,
    ) -> Result<Vec<Variable>, CircuitError> {
        let mut values = Vec::with_capacity(num_vals);

        // Chained hash of the seed value
        let mut hasher = PoseidonHashGadget::new(cs.zero() /* zero_var */);
        for _ in 0..num_vals {
            // Absorb the seed and then squeeze the next element
            hasher.absorb(seed, cs)?;
            seed = hasher.squeeze(cs)?;

            values.push(seed);

            // Reset the hasher state; we want the CSPRNG chain to be stateless, this
            // includes the internal state of the Poseidon sponge
            hasher.reset_state(cs);
        }

        Ok(values)
    }
}

// ---------------
// | Hash Gadget |
// ---------------

/// A hash gadget that applies a Poseidon hash function to the given constraint
/// system
///
/// This version of the gadget is used for the single-prover case, i.e. no MPC
#[derive(Clone, Debug)]
pub struct PoseidonHashGadget {
    /// The hash state
    state: Vec<Variable>,
    /// The next index in the state to being absorbing inputs at
    next_index: usize,
    /// Whether the sponge is in squeezing mode. For simplicity, we disallow
    /// the case in which a caller wishes to squeeze values and the absorb more.
    in_squeeze_state: bool,
}

impl PoseidonHashGadget {
    // -------------
    // | Interface |
    // -------------

    /// Construct a new hash gadget with the given parameterization
    pub fn new(zero_var: Variable) -> Self {
        // Initialize the state as all zeros
        let state = (0..CAPACITY + RATE).map(|_| zero_var).collect_vec();

        Self {
            state,
            next_index: 0,
            in_squeeze_state: false, // Start in absorb state
        }
    }

    /// Reset the internal state of the hasher
    pub fn reset_state<C: Circuit<ScalarField>>(&mut self, cs: &C) {
        let zero = cs.zero();
        self.state = (0..CAPACITY + RATE).map(|_| zero).collect_vec();
        self.next_index = 0;
        self.in_squeeze_state = false;
    }

    /// Hashes the given input and constraints the result to equal the expected
    /// output
    pub fn hash<C: Circuit<ScalarField>>(
        &mut self,
        hash_input: &[Variable],
        expected_output: Variable,
        cs: &mut C,
    ) -> Result<(), CircuitError> {
        self.batch_absorb(hash_input, cs)?;
        self.constrained_squeeze(expected_output, cs)
    }

    /// Absorb an input into the hasher state
    pub fn absorb<C: Circuit<ScalarField>>(
        &mut self,
        a: Variable,
        cs: &mut C,
    ) -> Result<(), CircuitError> {
        assert!(
            !self.in_squeeze_state,
            "Cannot absorb from a sponge that has already been squeezed"
        );

        // Permute the digest state if we have filled up the rate sized buffer
        if self.next_index == RATE {
            self.permute(cs)?;
            self.next_index = 0;
        }

        let access_index = self.next_index + CAPACITY;
        self.state[access_index] = cs.add(a, self.state[access_index])?;
        self.next_index += 1;
        Ok(())
    }

    /// Absorb a batch of inputs into the hasher state
    pub fn batch_absorb<C: Circuit<ScalarField>>(
        &mut self,
        a: &[Variable],
        cs: &mut C,
    ) -> Result<(), CircuitError> {
        a.iter().try_for_each(|val| self.absorb(*val, cs))
    }

    /// Squeeze an element from the sponge and return its representation in the
    /// constraint system
    pub fn squeeze<C: Circuit<ScalarField>>(
        &mut self,
        cs: &mut C,
    ) -> Result<Variable, CircuitError> {
        // Once we exit the absorb state, ensure that the digest state is permuted
        // before squeezing
        if !self.in_squeeze_state || self.next_index == RATE {
            self.permute(cs)?;
            self.next_index = 0;
            self.in_squeeze_state = true;
        }

        let res = self.state[CAPACITY + self.next_index];
        self.next_index += 1;
        Ok(res)
    }

    /// Squeeze a batch of elements from the sponge and return their
    /// representation in the constraint system
    pub fn batch_squeeze<C: Circuit<ScalarField>>(
        &mut self,
        num_elements: usize,
        cs: &mut C,
    ) -> Result<Vec<Variable>, CircuitError> {
        (0..num_elements).map(|_| self.squeeze(cs)).collect()
    }

    /// Squeeze an output from the hasher, and constraint its value to equal the
    /// provided statement variable.
    pub fn constrained_squeeze<C: Circuit<ScalarField>>(
        &mut self,
        expected: Variable,
        cs: &mut C,
    ) -> Result<(), CircuitError> {
        let squeezed_elem = self.squeeze(cs)?;
        cs.enforce_equal(expected, squeezed_elem)?;
        Ok(())
    }

    /// Squeeze a set of elements from the hasher, and constraint the elements
    /// to be equal to the provided statement variables
    pub fn batch_constrained_squeeze<C: Circuit<ScalarField>>(
        &mut self,
        expected: &[Variable],
        cs: &mut C,
    ) -> Result<(), CircuitError> {
        expected.iter().try_for_each(|val| self.constrained_squeeze(*val, cs))
    }

    // -----------------------
    // | Permutation Helpers |
    // -----------------------

    /// Permute the state using the Poseidon 2 permutation
    ///
    /// Throughout the permutation, the arithmetization fuses the gates in
    /// between rounds, adding the round constants for the next round after the
    /// MDS multiplication in the current round.
    #[allow(clippy::missing_docs_in_private_items)]
    fn permute<C: Circuit<ScalarField>>(&mut self, cs: &mut C) -> Result<(), CircuitError> {
        // Begin by multiplying by the external round matrix
        // Fuse with the first round's constants
        self.external_mds_with_rc(&FULL_ROUND_CONSTANTS[0], cs)?;

        // --- First Set of External Rounds --- //

        // Compute full_rounds / 2 rounds of the permutation
        const HALF: usize = R_F / 2;
        for round in 0..(HALF - 1) {
            let rc = &FULL_ROUND_CONSTANTS[round + 1];
            self.external_sbox_mds_with_rc(rc, cs)?;
        }

        // Last external round
        // Fuse the external MDS with the first internal round's constant
        let mut rc = [ScalarField::zero(); 3];
        rc[0] = PARTIAL_ROUND_CONSTANTS[0];
        self.external_sbox_mds_with_rc(&rc, cs)?;

        // --- Internal Rounds --- //

        // Compute the internal rounds of the permutation
        for round in 0..(R_P - 1) {
            rc[0] = PARTIAL_ROUND_CONSTANTS[round + 1];
            self.fused_internal_sbox_mds(&rc, cs)?;
        }

        // Last internal round
        // Fuse the internal MDS with the next external round's constants
        let rc = FULL_ROUND_CONSTANTS[HALF];
        self.fused_internal_sbox_mds(&rc, cs)?;

        // --- Second Set of External Rounds --- //

        // Compute another full_rounds / 2 rounds of the permutation
        for round in HALF..(R_F - 1) {
            let rc = &FULL_ROUND_CONSTANTS[round + 1];
            self.external_sbox_mds_with_rc(rc, cs)?;
        }

        // Last external round
        // Do not apply a round constant after the last MDS multiplication
        let rc = [ScalarField::zero(); 3];
        self.external_sbox_mds_with_rc(&rc, cs)?;

        Ok(())
    }

    // --- External Round Helpers --- //

    /// Apply the external MDS matrix, with a trailing round constant
    fn external_mds_with_rc<C: Circuit<ScalarField>>(
        &mut self,
        next_round_constants: &[ScalarField],
        cs: &mut C,
    ) -> Result<(), CircuitError> {
        self.fused_external_mds_with_rc(false /* sbox */, next_round_constants, cs)
    }

    /// Execute a fused external sbox and MDS matrix multiplication with a
    /// trailing round constant
    fn external_sbox_mds_with_rc<C: Circuit<ScalarField>>(
        &mut self,
        next_round_const: &[ScalarField],
        cs: &mut C,
    ) -> Result<(), CircuitError> {
        self.fused_external_mds_with_rc(true /* sbox */, next_round_const, cs)
    }

    /// A fused external MDS matrix multiplication with a trailing round
    /// constant
    ///
    /// Optionally, the sbox may be applied before the MDS multiplication
    ///
    /// The trailing round constant allows successive rounds to fuse in the
    /// permutation, with this gate finishing one round and adding the round
    /// constant the defines the start of the next round
    fn fused_external_mds_with_rc<C: Circuit<ScalarField>>(
        &mut self,
        apply_sbox: bool,
        next_round_const: &[ScalarField],
        cs: &mut C,
    ) -> Result<(), CircuitError> {
        let in_wires = self.state.clone();

        // First state element
        let rc = next_round_const[0];
        let state_elem = self.state[0];
        let out_var =
            self.add_fused_external_sbox_mds(apply_sbox, rc, state_elem, &in_wires, cs)?;
        self.state[0] = out_var;

        // Second state element
        let rc = next_round_const[1];
        let state_elem = self.state[1];
        let out_var =
            self.add_fused_external_sbox_mds(apply_sbox, rc, state_elem, &in_wires, cs)?;
        self.state[1] = out_var;

        // Third state element
        let rc = next_round_const[2];
        let state_elem = self.state[2];
        let out_var =
            self.add_fused_external_sbox_mds(apply_sbox, rc, state_elem, &in_wires, cs)?;
        self.state[2] = out_var;

        Ok(())
    }

    /// A fused external sbox and MDS matrix multiplication with a trailing
    /// round constant
    fn add_fused_external_sbox_mds<C: Circuit<ScalarField>>(
        &self,
        apply_sbox: bool,
        rc: ScalarField,
        curr_state: Variable,
        state_vars: &[Variable],
        cs: &mut C,
    ) -> Result<Variable, CircuitError> {
        let gate = FusedExternalSboxMDSGate::new(apply_sbox, rc);

        let state_curr = cs.witness(curr_state)?;
        let state0 = cs.witness(state_vars[0])?;
        let state1 = cs.witness(state_vars[1])?;
        let state2 = cs.witness(state_vars[2])?;
        let out = gate.compute_output::<C>(state_curr, state0, state1, state2);
        let out_var = cs.create_variable(out)?;

        let wires = [curr_state, state_vars[0], state_vars[1], state_vars[2], out_var];
        cs.insert_gate(&wires, Box::new(gate))?;
        Ok(out_var)
    }

    // --- Internal Round Helpers --- //

    /// A fused internal sbox and MDS matrix multiplication with a trailing
    /// round constant
    ///
    /// Though internal rounds only apply round constants to the first state
    /// element, this method accepts a list of round constants to allow its
    /// gate to fuse with a subsequent external round
    fn fused_internal_sbox_mds<C: Circuit<ScalarField>>(
        &mut self,
        next_round_constants: &[ScalarField],
        cs: &mut C,
    ) -> Result<(), CircuitError> {
        let in_wires = self.state.clone();

        // First state element
        let state_coeff = ScalarField::one();
        let next_round_constant = next_round_constants[0];
        let state_elem = self.state[0];
        let out_var = self.add_fused_internal_sbox_mds(
            true, // sbox
            next_round_constant,
            state_coeff,
            state_elem,
            &in_wires,
            cs,
        )?;
        self.state[0] = out_var;

        // Second state element
        let state_coeff = ScalarField::one();
        let next_round_constant = next_round_constants[1];
        let state_elem = self.state[1];
        let out_var = self.add_fused_internal_sbox_mds(
            false, // no sbox
            next_round_constant,
            state_coeff,
            state_elem,
            &in_wires,
            cs,
        )?;
        self.state[1] = out_var;

        // Third state element
        let state_coeff = ScalarField::from(2u8);
        let next_round_constant = next_round_constants[2];
        let state_elem = self.state[2];
        let out_var = self.add_fused_internal_sbox_mds(
            false, // no sbox
            next_round_constant,
            state_coeff,
            state_elem,
            &in_wires,
            cs,
        )?;
        self.state[2] = out_var;

        Ok(())
    }

    /// Add a fused internal sbox + MDS gate to the constraint system
    fn add_fused_internal_sbox_mds<C: Circuit<ScalarField>>(
        &self,
        apply_sbox: bool,
        next_round_constant: ScalarField,
        state_elem_coeff: ScalarField,
        curr_state: Variable,
        state_vars: &[Variable],
        cs: &mut C,
    ) -> Result<Variable, CircuitError> {
        let gate = FusedInternalSboxMDSGate::new(apply_sbox, next_round_constant, state_elem_coeff);

        // Compute the output of the gate
        let state_curr = cs.witness(curr_state)?;
        let state0 = cs.witness(state_vars[0])?;
        let state1 = cs.witness(state_vars[1])?;
        let state2 = cs.witness(state_vars[2])?;
        let out = gate.compute_output::<C>(state_curr, state0, state1, state2);
        let out_var = cs.create_variable(out)?;

        let wires = [curr_state, state_vars[0], state_vars[1], state_vars[2], out_var];
        cs.insert_gate(&wires, Box::new(gate))?;
        Ok(out_var)
    }
}
