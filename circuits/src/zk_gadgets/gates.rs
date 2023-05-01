//! Groups logical gate gadgets used in ZK circuits

use std::marker::PhantomData;

use curve25519_dalek::scalar::Scalar;
use mpc_bulletproof::{
    r1cs::{LinearCombination, RandomizableConstraintSystem, Variable},
    r1cs_mpc::{MpcLinearCombination, MpcRandomizableConstraintSystem},
};
use mpc_ristretto::{beaver::SharedValueSource, network::MpcNetwork};

use crate::{errors::ProverError, zk_gadgets::comparators::EqGadget};

/// Represents an OR gate in a single-prover constraint system
pub struct OrGate;
impl OrGate {
    /// Computes the logical OR of the two arguments
    ///
    /// The arguments are assumed to be binary (0 or 1), but this assumption should be
    /// constrained elsewhere in the calling circuit
    pub fn or<L, CS>(a: L, b: L, cs: &mut CS) -> LinearCombination
    where
        L: Into<LinearCombination>,
        CS: RandomizableConstraintSystem,
    {
        let (a, b, a_times_b) = cs.multiply(a.into(), b.into());
        a + b - a_times_b
    }

    /// Computes the logical OR of `n` arguments: out = a_1 || a_2 || .. || a_n
    ///
    /// The arguments are assumed to be binary (0 or 1), but this assumption should be
    /// constrained elsewhere in the calling circuit
    pub fn multi_or<L, CS>(a: &[L], cs: &mut CS) -> LinearCombination
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        // Dispatch to the single OR gate
        a.iter().fold(Variable::Zero().into(), |acc, val| {
            Self::or(acc, val.clone().into(), cs)
        })
    }
}

/// Represents an OR gate in a multi-prover constraint system
pub struct MultiproverOrGate<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// Phantom
    _phantom: &'a PhantomData<(N, S)>,
}

impl<'a, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>> MultiproverOrGate<'a, N, S> {
    /// Return the logical OR of the two arguments
    ///
    /// The arguments are assumed to be binary (0 or 1), but this assumption should be
    /// constrained elsewhere in the calling circuit
    pub fn or<L, CS>(a: L, b: L, cs: &mut CS) -> Result<MpcLinearCombination<N, S>, ProverError>
    where
        L: Into<MpcLinearCombination<N, S>> + Clone,
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
    {
        let (a, b, a_times_b) = cs
            .multiply(&a.into(), &b.into())
            .map_err(ProverError::Collaborative)?;
        Ok(&a + &b - a_times_b)
    }
}

/// Represents an AND gate in the constraint system
#[derive(Clone, Debug)]
pub struct AndGate;
impl AndGate {
    /// Computes the logical AND of the two inputs: out = a & b
    ///
    /// The arguments are assumed to be binary (0 or 1), but this assumption should be
    /// constrained elsewhere in the calling circuit
    pub fn and<L, CS>(a: L, b: L, cs: &mut CS) -> Variable
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        // For binary values, and is reduced to multiplication
        // Multiply the values and return their output wire
        cs.multiply(a.into(), b.into()).2
    }

    /// Computes the logical AND of `n` inputs: out = a_1 & a_2 & ... & a_n
    ///
    /// The arguments are assumed to be binary (0 or 1), but this assumption should be
    /// constrained elsewhere in the calling circuit
    pub fn multi_and<L, CS>(a: &[L], cs: &mut CS) -> Variable
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        let sum: LinearCombination = a
            .iter()
            .cloned()
            .fold(Variable::Zero().into(), |acc, val| acc + val);
        EqGadget::eq(sum, Scalar::from(a.len() as u32).into(), cs)
    }
}

/// Inverts a boolean assumed to be constrained binary
#[derive(Clone, Debug)]
pub struct NotGate;
impl NotGate {
    /// Computes the logical NOT of an input boolean: out = !a
    ///
    /// The argument is assumed to be binary (0 or 1), but this assumption should be
    /// constrained elsewhere in the calling circuit
    pub fn not<L, CS>(a: L, _cs: &mut CS) -> LinearCombination
    where
        L: Into<LinearCombination>,
        CS: RandomizableConstraintSystem,
    {
        Variable::One() - a.into()
    }
}

/// Constrains an input value to be binary; 0 or 1
#[derive(Clone, Debug)]
pub struct ConstrainBinaryGadget {}
impl ConstrainBinaryGadget {
    /// Constrain the input to be binary (0 or 1), this is done by constraining
    /// the polynomial x * (1 - x) which is only satisfied when x \in {0, 1}
    pub fn constrain_binary<L, CS>(x: L, cs: &mut CS)
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        let x_lc: LinearCombination = x.into();
        let mul_out = cs.multiply(x_lc.clone(), Variable::One() - x_lc).2;
        cs.constrain(mul_out.into());
    }
}
