//! Groups logic for adding Poseidon hash function constraints to a Bulletproof
//! constraint system

use std::ops::Mul;

use crate::print_wire;
use ark_ff::{Field, One, Zero};
use ark_mpc::algebra::FieldWrapper;
use constants::ScalarField;
use itertools::Itertools;
use jf_primitives::rescue::STATE_SIZE;
use mpc_relation::{
    constants::GATE_WIDTH, errors::CircuitError, gates::Gate, traits::Circuit, Variable,
};
use renegade_crypto::hash::{
    CAPACITY, FULL_ROUND_CONSTANTS, PARTIAL_ROUND_CONSTANTS, RATE, R_F, R_P, WIDTH as SPONGE_WIDTH,
};

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

    /// Permute the state using the Poseidon 2 permutation
    #[allow(clippy::missing_docs_in_private_items)]
    fn permute<C: Circuit<ScalarField>>(&mut self, cs: &mut C) -> Result<(), CircuitError> {
        // Multiply by the external round matrix
        self.external_mds(cs)?;

        // Compute full_rounds / 2 rounds of the permutation
        const HALF: usize = R_F / 2;
        for round in 0..HALF {
            self.external_round(round, cs)?;
        }

        // Compute the partial rounds of the permutation
        for round in 0..R_P {
            self.internal_round(round, cs)?;
        }

        // Compute another full_rounds / 2 rounds of the permutation
        for round in HALF..R_F {
            self.external_round(round, cs)?;
        }

        Ok(())
    }

    /// Run an external round on the state
    fn external_round<C: Circuit<ScalarField>>(
        &mut self,
        round_number: usize,
        cs: &mut C,
    ) -> Result<(), CircuitError> {
        self.external_add_rc(round_number, cs)?;
        self.external_sbox(cs)?;
        self.external_mds(cs)
    }

    /// Add round constants in an external round
    fn external_add_rc<C: Circuit<ScalarField>>(
        &mut self,
        round_number: usize,
        cs: &mut C,
    ) -> Result<(), CircuitError> {
        let rc = &FULL_ROUND_CONSTANTS[round_number];
        for (state_elem, rc) in self.state.iter_mut().zip(rc.iter()) {
            *state_elem = cs.add_constant(*state_elem, rc)?;
        }

        Ok(())
    }

    /// Apply the sbox to the state in an external round
    fn external_sbox<C: Circuit<ScalarField>>(&mut self, cs: &mut C) -> Result<(), CircuitError> {
        for state_elem in self.state.iter_mut() {
            *state_elem = cs.pow5(*state_elem)?;
        }

        Ok(())
    }

    /// Apply the external MDS matrix to the state
    ///
    /// For t = 3, this is the circulant matrix `circ(2, 1, 1)`
    ///
    /// This is equivalent to doubling each element then adding the other two to
    /// it, or more efficiently: adding the sum of the elements to each
    /// individual element. This efficient structure is borrowed from:
    ///     https://github.com/HorizenLabs/poseidon2/blob/main/plain_implementations/src/poseidon2/poseidon2.rs#L129-L137
    fn external_mds<C: Circuit<ScalarField>>(&mut self, cs: &mut C) -> Result<(), CircuitError> {
        let coeffs = [ScalarField::one(); GATE_WIDTH];
        let in_wires = self.state.clone();
        for state_elem in self.state.iter_mut() {
            let lc_wires = [*state_elem, in_wires[0], in_wires[1], in_wires[2]];
            *state_elem = cs.lc(&lc_wires, &coeffs)?;
        }

        Ok(())
    }

    /// Run an internal round on the state
    fn internal_round<C: Circuit<ScalarField>>(
        &mut self,
        round_number: usize,
        cs: &mut C,
    ) -> Result<(), CircuitError> {
        self.internal_add_rc(round_number, cs)?;
        self.fused_internal_sbox_mds(cs)
    }

    /// Add round constants in an internal round
    fn internal_add_rc<C: Circuit<ScalarField>>(
        &mut self,
        round_number: usize,
        cs: &mut C,
    ) -> Result<(), CircuitError> {
        let rc = &PARTIAL_ROUND_CONSTANTS[round_number];
        self.state[0] = cs.add_constant(self.state[0], rc)?;

        Ok(())
    }

    /// Apply the sbox to the state in an internal round
    fn internal_sbox<C: Circuit<ScalarField>>(&mut self, cs: &mut C) -> Result<(), CircuitError> {
        self.state[0] = cs.pow5(self.state[0])?;
        Ok(())
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
    fn internal_mds<C: Circuit<ScalarField>>(&mut self, cs: &mut C) -> Result<(), CircuitError> {
        let mut coeffs = [ScalarField::one(); GATE_WIDTH];
        let in_wires = self.state.clone();

        // The first two elements of the state
        for state_elem in self.state[..SPONGE_WIDTH - 1].iter_mut() {
            let lc_wires = [*state_elem, in_wires[0], in_wires[1], in_wires[2]];
            *state_elem = cs.lc(&lc_wires, &coeffs)?;
        }

        // The last element of the state requires an additional copy of itself
        coeffs[0] = ScalarField::from(2u8);
        let lc_wires = [self.state[SPONGE_WIDTH - 1], in_wires[0], in_wires[1], in_wires[2]];
        self.state[SPONGE_WIDTH - 1] = cs.lc(&lc_wires, &coeffs)?;

        Ok(())
    }

    /// A fused internal sbox and MDS matrix
    fn fused_internal_sbox_mds<C: Circuit<ScalarField>>(
        &mut self,
        cs: &mut C,
    ) -> Result<(), CircuitError> {
        let in_wires = self.state.clone();

        // First state element
        let state_coeff = ScalarField::one();
        let state_elem = self.state[0];
        let out_var = self.add_fused_internal_sbox_mds(
            state_coeff,
            true, // sbox
            state_elem,
            &in_wires,
            cs,
        )?;
        self.state[0] = out_var;

        // Second state element
        let state_coeff = ScalarField::one();
        let state_elem = self.state[1];
        let out_var = self.add_fused_internal_sbox_mds(
            state_coeff,
            false, // no sbox
            state_elem,
            &in_wires,
            cs,
        )?;
        self.state[1] = out_var;

        // Third state element
        let state_coeff = ScalarField::from(2u8);
        let state_elem = self.state[2];
        let out_var = self.add_fused_internal_sbox_mds(
            state_coeff,
            false, // no sbox
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
        state_elem_coeff: ScalarField,
        apply_sbox: bool,
        curr_state: Variable,
        state_vars: &[Variable],
        cs: &mut C,
    ) -> Result<Variable, CircuitError> {
        let gate = FusedInternalSboxMDSGate::new(state_elem_coeff, apply_sbox);

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

// -------------------------
// | Poseidon Custom Gates |
// -------------------------

/// Represents a fused internal sbox and the first step in the internal MDS
/// matmul, summing the inputs
///
/// Implements (a_1 * state0^5 + a_2 * state1 + a_3 * state2)
#[derive(Copy, Clone)]
struct FusedInternalSboxMDSGate<F: Field> {
    /// The coefficients of the linear combination
    state_elem_coeff: F,
    /// Whether or not to apply the sbox to the state element
    apply_sbox: bool,
}

impl<F: Field> FusedInternalSboxMDSGate<F> {
    /// Create a new fused internal sbox and MDS gate
    fn new(state_elem_coeff: F, apply_sbox: bool) -> Self {
        Self { state_elem_coeff, apply_sbox }
    }

    /// Compute the output of the gate given the input wire assignments
    fn compute_output<C: Circuit<F>>(
        &self,
        state_curr: C::Wire,
        state0: C::Wire,
        state1: C::Wire,
        state2: C::Wire,
    ) -> C::Wire {
        let curr_coeff = C::Constant::from_field(&self.state_elem_coeff);
        let state_elem = if self.apply_sbox { Self::pow5::<C>(state_curr) } else { state_curr };
        curr_coeff * state_elem + Self::pow5::<C>(state0) + state1 + state2
    }

    /// Compute the fifth power of a wire
    fn pow5<C: Circuit<F>>(x: C::Wire) -> C::Wire {
        let x2 = x.clone() * x.clone();
        let x4 = x2.clone() * x2.clone();
        x4 * x
    }
}

impl<F: Field> Gate<F> for FusedInternalSboxMDSGate<F> {
    fn name(&self) -> &'static str {
        "FusedInternalSboxMDSGate"
    }

    fn q_hash(&self) -> [F; GATE_WIDTH] {
        // If we are applying the sbox to the state element, we enable the first
        // hash gate
        if self.apply_sbox {
            [self.state_elem_coeff, F::one(), F::zero(), F::zero()]
        } else {
            [F::zero(), F::one(), F::zero(), F::zero()]
        }
    }

    fn q_lc(&self) -> [F; GATE_WIDTH] {
        if self.apply_sbox {
            [F::zero(), F::zero(), F::one(), F::one()]
        } else {
            [self.state_elem_coeff, F::zero(), F::one(), F::one()]
        }
    }

    fn q_o(&self) -> F {
        F::one()
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    use circuit_types::{traits::CircuitBaseType, PlonkCircuit};
    use constants::Scalar;
    use itertools::Itertools;
    use mpc_relation::traits::Circuit;
    use rand::thread_rng;
    use renegade_crypto::hash::{compute_poseidon_hash, Poseidon2Sponge};

    use crate::zk_gadgets::poseidon::PoseidonHashGadget;

    #[test]
    fn test_n_constraints() {
        const N: usize = 100;
        let mut cs = PlonkCircuit::new_turbo_plonk();

        let input = vec![cs.one()];
        let expected_output = cs.one();
        for _ in 0..N {
            let mut hasher = PoseidonHashGadget::new(cs.zero());
            hasher.hash(&input, expected_output, &mut cs).unwrap();
        }

        println!("{}", cs.num_gates());
    }

    /// Tests absorbing a series of elements into the hasher and comparing to
    /// the hasher in `renegade-crypto`
    #[test]
    fn test_sponge() {
        const N: usize = 100;
        let mut rng = thread_rng();
        let values = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();

        let expected = compute_poseidon_hash(&values);

        // Constrain the gadget result
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let mut gadget = PoseidonHashGadget::new(cs.zero());

        // Allocate the values in the constraint system
        let input_vars = values.iter().map(|v| v.create_witness(&mut cs)).collect_vec();
        let output_var = expected.create_public_var(&mut cs);

        gadget.hash(&input_vars, output_var, &mut cs).unwrap();

        // Check that the constraints are satisfied
        assert!(cs.check_circuit_satisfiability(&[expected.inner()]).is_ok());
    }

    /// Tests a batch absorb and squeeze of the hasher
    #[test]
    fn test_batch_absorb_squeeze() {
        const N: usize = 5;
        let mut rng = thread_rng();
        let absorb_values = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();

        // Compute the expected result
        let mut hasher = Poseidon2Sponge::new();
        hasher.absorb_batch(&absorb_values.iter().map(Scalar::inner).collect_vec());
        let expected_squeeze_values =
            hasher.squeeze_batch(N).into_iter().map(Scalar::new).collect_vec();

        // Compute the result in-circuit
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let mut gadget = PoseidonHashGadget::new(cs.zero());
        let absorb_vars = absorb_values.iter().map(|v| v.create_witness(&mut cs)).collect_vec();

        gadget.batch_absorb(&absorb_vars, &mut cs).unwrap();
        let squeeze_vars = gadget.batch_squeeze(N, &mut cs).unwrap();

        // Check that the squeezed values match the expected values
        for (squeeze_var, expected_value) in
            squeeze_vars.into_iter().zip(expected_squeeze_values.into_iter())
        {
            let expected_var = expected_value.create_witness(&mut cs);
            cs.enforce_equal(squeeze_var, expected_var).unwrap();
        }

        // Check that the constraints are satisfied
        assert!(cs.check_circuit_satisfiability(&[]).is_ok());
    }
}
