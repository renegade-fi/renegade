//! Poseidon hash gadget gates

use ark_ff::Field;
use ark_mpc::algebra::FieldWrapper;
use mpc_relation::{constants::GATE_WIDTH, gates::Gate, traits::Circuit};

// ------------------------
// | External Round Gates |
// ------------------------

/// Represents a fused external sbox and  external MDS matrix multiplication per
/// state element
///
/// Implements a_1^5 + a_2^5 + a_3^5 + a_4^5
#[derive(Copy, Clone)]
pub struct FusedExternalSboxMDSGate<F> {
    /// Whether or not to apply the sbox to the state
    apply_sbox: bool,
    /// A round constant to add after the MDS is applied
    ///
    /// This allows the arithmetization to fuse the gates in between rounds
    /// in the permutation, adding the round constant for the next round after
    /// the MDS multiplication in the current round
    round_constant: F,
}

impl<F: Field> FusedExternalSboxMDSGate<F> {
    /// Create a new fused external sbox and MDS gate
    pub fn new(apply_sbox: bool, round_constant: F) -> Self {
        Self { apply_sbox, round_constant }
    }

    /// Compute the output of the gate given the input wire assignments
    pub fn compute_output<C: Circuit<F>>(
        &self,
        state_curr: C::Wire,
        state0: C::Wire,
        state1: C::Wire,
        state2: C::Wire,
    ) -> C::Wire {
        let mut elements = vec![state_curr, state0, state1, state2];
        if self.apply_sbox {
            elements = Self::pow5_elements::<C>(&elements);
        }

        let state_curr = elements[0].clone();
        let state0 = elements[1].clone();
        let state1 = elements[2].clone();
        let state2 = elements[3].clone();
        let rc = C::Constant::from_field(&self.round_constant);
        rc + state_curr + state0 + state1 + state2
    }

    /// Compute the fifth power of each element in the input vector
    fn pow5_elements<C: Circuit<F>>(elements: &[C::Wire]) -> Vec<C::Wire> {
        elements.iter().cloned().map(pow5::<F, C>).collect()
    }
}

impl<F: Field> Gate<F> for FusedExternalSboxMDSGate<F> {
    fn name(&self) -> &'static str {
        "FusedExternalSboxMDSGate"
    }

    fn q_hash(&self) -> [F; GATE_WIDTH] {
        if self.apply_sbox {
            [F::one(), F::one(), F::one(), F::one()]
        } else {
            [F::zero(), F::zero(), F::zero(), F::zero()]
        }
    }

    fn q_lc(&self) -> [F; GATE_WIDTH] {
        if self.apply_sbox {
            [F::zero(), F::zero(), F::zero(), F::zero()]
        } else {
            [F::one(), F::one(), F::one(), F::one()]
        }
    }

    fn q_c(&self) -> F {
        self.round_constant
    }

    fn q_o(&self) -> F {
        F::one()
    }
}

/// Compute the fifth power of a wire
fn pow5<F: Field, C: Circuit<F>>(x: C::Wire) -> C::Wire {
    let x2 = x.clone() * x.clone();
    let x4 = x2.clone() * x2.clone();
    x4 * x
}

// ------------------------
// | Internal Round Gates |
// ------------------------

/// Represents a fused internal sbox and the first step in the internal MDS
/// matmul, summing the inputs
///
/// Implements (a_1 * state0^5 + a_2 * state1 + a_3 * state2)
#[derive(Copy, Clone)]
pub struct FusedInternalSboxMDSGate<F: Field> {
    /// Whether or not to apply the sbox to the state element
    apply_sbox: bool,
    /// The round constant to add after the MDS is applied
    next_round_constant: F,
    /// The coefficients of the linear combination
    state_elem_coeff: F,
}

impl<F: Field> FusedInternalSboxMDSGate<F> {
    /// Create a new fused internal sbox and MDS gate
    pub fn new(apply_sbox: bool, next_round_constant: F, state_elem_coeff: F) -> Self {
        Self { apply_sbox, next_round_constant, state_elem_coeff }
    }

    /// Compute the output of the gate given the input wire assignments
    pub fn compute_output<C: Circuit<F>>(
        &self,
        state_curr: C::Wire,
        state0: C::Wire,
        state1: C::Wire,
        state2: C::Wire,
    ) -> C::Wire {
        let curr_coeff = C::Constant::from_field(&self.state_elem_coeff);
        let state_elem = if self.apply_sbox { pow5::<F, C>(state_curr) } else { state_curr };
        let rc = C::Constant::from_field(&self.next_round_constant);

        rc + curr_coeff * state_elem + pow5::<F, C>(state0) + state1 + state2
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

    fn q_c(&self) -> F {
        self.next_round_constant
    }

    fn q_o(&self) -> F {
        F::one()
    }
}
