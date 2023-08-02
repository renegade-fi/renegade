//! Groups gadgets for binary comparison operators

use std::marker::PhantomData;

use circuit_types::{
    errors::ProverError,
    traits::{
        CircuitVarType, LinearCombinationLike, MpcLinearCombinationLike,
        MultiproverCircuitVariableType,
    },
};
use itertools::Itertools;
use mpc_bulletproof::{
    r1cs::{LinearCombination, RandomizableConstraintSystem, Variable},
    r1cs_mpc::{MpcLinearCombination, MpcRandomizableConstraintSystem},
};
use mpc_stark::{algebra::scalar::Scalar, MpcFabric};

use crate::{
    mpc_gadgets::bits::to_bits_le, zk_gadgets::bits::scalar_to_bits_le, POSITIVE_SCALAR_MAX_BITS,
};

/// A gadget that returns whether a value is equal to zero
///
/// Its output is Variable::One() if the input is equal to zero,
/// or Variable::Zero() if not
#[derive(Clone, Debug)]
pub struct EqZeroGadget {}
impl EqZeroGadget {
    /// Computes whether the given input is equal to zero
    ///
    /// Relies on the fact that modulo a prime field, all elements (except zero)
    /// have a valid multiplicative inverse
    pub fn eq_zero<L, CS>(val: L, cs: &mut CS) -> Variable
    where
        L: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    {
        // Compute the inverse of the value outside the constraint
        let val_lc: LinearCombination = val.into();
        let val_eval = cs.eval(&val_lc);

        let (is_zero, inverse) = if val_eval == Scalar::zero() {
            (Scalar::one(), Scalar::zero())
        } else {
            (Scalar::zero(), val_eval.inverse())
        };

        // Constrain the inverse to be computed correctly and such that
        //  is_zero == 1 - inv * val
        // If the input is zero, inv * val should be zero, and is_zero should be one
        // If the input is non-zero, inv * val should be one, and is_zero should be zero
        let is_zero_var = cs.allocate(Some(is_zero)).unwrap();
        let inv_var = cs.allocate(Some(inverse)).unwrap();
        let (_, _, val_times_inv) = cs.multiply(val_lc.clone(), inv_var.into());
        cs.constrain(is_zero_var - Scalar::one() + val_times_inv);

        // Constrain the input times the output to equal zero, this handles the edge case in the
        // above constraint in which the value is one, the prover assigns inv and is_zero such
        // that inv is neither zero nor one
        // I.e. the only way to satisfy this constraint when the value is non-zero is if is_zero == 0
        let (_, _, in_times_out) = cs.multiply(val_lc, is_zero_var.into());
        cs.constrain(in_times_out.into());

        is_zero_var
    }
}

/// Returns 1 if a == b otherwise 0
#[derive(Clone, Debug)]
pub struct EqGadget {}
impl EqGadget {
    /// Computes a == b
    pub fn eq<L1, L2, V1, V2, CS>(a: V1, b: V2, cs: &mut CS) -> Variable
    where
        L1: LinearCombinationLike,
        L2: LinearCombinationLike,
        V1: CircuitVarType<L1>,
        V2: CircuitVarType<L2>,
        CS: RandomizableConstraintSystem,
    {
        let a_vars = a.to_vars();
        let b_vars = b.to_vars();

        EqVecGadget::eq_vec(&a_vars, &b_vars, cs)
    }

    /// Constraints a == b
    pub fn constrain_eq<L1, L2, V1, V2, CS>(a: V1, b: V2, cs: &mut CS)
    where
        L1: LinearCombinationLike,
        L2: LinearCombinationLike,
        V1: CircuitVarType<L1>,
        V2: CircuitVarType<L2>,
        CS: RandomizableConstraintSystem,
    {
        let a_vars = a.to_vars();
        let b_vars = b.to_vars();
        assert!(
            a_vars.len() == b_vars.len(),
            "a and b must have the same length"
        );

        EqVecGadget::constrain_eq_vec(&a_vars, &b_vars, cs)
    }
}

/// Returns 1 if a_i = b_i for all i, otherwise 0
#[derive(Clone, Debug)]
pub struct EqVecGadget {}
impl EqVecGadget {
    /// Returns 1 if \vec{a} = \vec{b}, otherwise 0
    pub fn eq_vec<L1, L2, V1, V2, CS>(a: &[V1], b: &[V2], cs: &mut CS) -> Variable
    where
        L1: LinearCombinationLike,
        L2: LinearCombinationLike,
        V1: CircuitVarType<L1>,
        V2: CircuitVarType<L2>,
        CS: RandomizableConstraintSystem,
    {
        assert_eq!(a.len(), b.len(), "eq_vec expects equal length vectors");
        let a_vals = a
            .iter()
            .cloned()
            .flat_map(|a_val| a_val.to_vars())
            .collect_vec();
        let b_vals = b
            .iter()
            .cloned()
            .flat_map(|b_val| b_val.to_vars())
            .collect_vec();

        // Compare each vector element
        let mut not_equal_values = Vec::with_capacity(a.len());
        for (a_val, b_val) in a_vals.into_iter().zip(b_vals.into_iter()) {
            not_equal_values.push(NotEqualGadget::not_equal(a_val.clone(), b_val.clone(), cs));
        }

        // Sum up all the a_i != b_i and return whether this value equals zero
        let mut not_equal_sum: LinearCombination = Variable::Zero().into();
        for ne_val in not_equal_values.iter() {
            not_equal_sum += ne_val.clone();
        }

        EqZeroGadget::eq_zero(not_equal_sum, cs)
    }

    /// Constraints the two vectors to be equal
    pub fn constrain_eq_vec<L1, L2, V1, V2, CS>(a: &[V1], b: &[V2], cs: &mut CS)
    where
        L1: LinearCombinationLike,
        L2: LinearCombinationLike,
        V1: CircuitVarType<L1>,
        V2: CircuitVarType<L2>,
        CS: RandomizableConstraintSystem,
    {
        assert_eq!(a.len(), b.len(), "eq_vec expects equal length vectors");
        let a_vars = a
            .iter()
            .cloned()
            .flat_map(|a_val| a_val.to_vars())
            .collect_vec();
        let b_vars = b
            .iter()
            .cloned()
            .flat_map(|b_val| b_val.to_vars())
            .collect_vec();

        for (a_val, b_val) in a_vars.into_iter().zip(b_vars) {
            let a_lc: LinearCombination = a_val.into();
            let b_lc: LinearCombination = b_val.into();
            cs.constrain(a_lc - b_lc);
        }
    }
}

/// Returns a boolean representing a != b where 1 is true and 0 is false
#[derive(Debug)]
pub struct NotEqualGadget {}
impl NotEqualGadget {
    /// Computes a != b
    pub fn not_equal<L1, L2, CS>(a: L1, b: L2, cs: &mut CS) -> LinearCombination
    where
        L1: LinearCombinationLike,
        L2: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    {
        let eq_zero = EqZeroGadget::eq_zero(a.into() - b.into(), cs);
        Variable::One() - eq_zero
    }
}

/// A gadget that enforces a value of a given bitlength is positive
#[derive(Clone, Debug)]
pub struct GreaterThanEqZeroGadget<const D: usize> {}
impl<const D: usize> GreaterThanEqZeroGadget<D> {
    /// Evaluate the condition x >= 0; returns 1 if true, otherwise 0
    pub fn greater_than_zero<L, CS>(x: L, cs: &mut CS) -> Variable
    where
        L: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    {
        // If we can reconstruct the value without the highest bit, the value is non-negative
        let bit_reconstructed = Self::bit_decompose_reconstruct(x.clone(), cs);
        EqZeroGadget::eq_zero(bit_reconstructed - x.into(), cs)
    }

    /// Constrain the value to be greater than zero
    pub fn constrain_greater_than_zero<L, CS>(x: L, cs: &mut CS)
    where
        L: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    {
        // If we can reconstruct the value without the highest bit, the value is non-negative
        let bit_reconstructed = Self::bit_decompose_reconstruct(x.clone(), cs);
        cs.constrain(bit_reconstructed - x.into())
    }

    /// A helper function to decompose a scalar into bits and then reconstruct it;
    /// returns the reconstructed result
    ///
    /// This is used by limiting the bit width of the decomposition -- if a value can
    /// be reconstructed without its highest bit (i.e. highest bit is zero) then it is
    /// non-negative
    fn bit_decompose_reconstruct<L, CS>(x: L, cs: &mut CS) -> LinearCombination
    where
        L: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    {
        assert!(
            D <= POSITIVE_SCALAR_MAX_BITS,
            "a positive value may only have {:?} bits",
            POSITIVE_SCALAR_MAX_BITS
        );

        // Bit decompose the input
        let bits = scalar_to_bits_le::<D>(&cs.eval(&x.into()))[..D]
            .iter()
            .map(|bit| cs.allocate(Some(*bit)).unwrap())
            .collect_vec();

        // Constrain the bit decomposition to be correct
        // This implicitly constrains the value to be greater than zero, i.e. if it can be represented
        // without the highest bit set, then it is greater than zero. This assumes a two's complement
        // representation
        let mut res = LinearCombination::default();
        for bit in bits.into_iter().rev() {
            res = res * Scalar::from(2u64) + bit
        }

        res
    }
}

/// A multiprover version of the greater than or equal to zero gadget
pub struct MultiproverGreaterThanEqZeroGadget<'a, const D: usize> {
    /// Phantom
    _phantom: &'a PhantomData<()>,
}

impl<'a, const D: usize> MultiproverGreaterThanEqZeroGadget<'a, D> {
    /// Constrains the input value to be greater than or equal to zero implicitly
    /// by bit-decomposing the value and re-composing it thereafter
    pub fn constrain_greater_than_zero<L, CS>(
        x: L,
        fabric: MpcFabric,
        cs: &mut CS,
    ) -> Result<(), ProverError>
    where
        L: MpcLinearCombinationLike,
        CS: MpcRandomizableConstraintSystem<'a>,
    {
        let reconstructed_res = Self::bit_decompose_reconstruct(x.clone(), fabric, cs)?;
        cs.constrain(reconstructed_res - x.into());
        Ok(())
    }

    /// A helper function to compute the bit decomposition of an allocated scalar and
    /// then reconstruct from the bit decomposition.
    ///
    /// This is useful because we can bit decompose with all but the highest bit. If the
    /// reconstructed result is equal to the input; the highest bit is not set and the
    /// value is non-negative
    fn bit_decompose_reconstruct<L, CS>(
        x: L,
        fabric: MpcFabric,
        cs: &mut CS,
    ) -> Result<MpcLinearCombination, ProverError>
    where
        L: MpcLinearCombinationLike,
        CS: MpcRandomizableConstraintSystem<'a>,
    {
        // Evaluate the assignment of the value in the underlying constraint system
        let value_assignment = cs.eval(&x.into());
        let bits = to_bits_le::<D>(&value_assignment, fabric)
            .into_iter()
            .map(|bit| cs.allocate(Some(bit)).unwrap())
            .collect_vec();

        // Constrain the bit decomposition to be correct
        // This implicitly constrains the value to be greater than zero, i.e. if it can be represented
        // without the highest bit set, then it is greater than zero. This assumes a two's complement
        // representation
        let mut res = MpcLinearCombination::default();
        for bit in bits.into_iter().rev() {
            res = res * Scalar::from(2u64) + bit;
        }

        Ok(res)
    }
}

/// Enforces the constraint a >= b
///
/// `D` is the bitlength of the values being compared
pub struct GreaterThanEqGadget<const D: usize> {}
impl<const D: usize> GreaterThanEqGadget<D> {
    /// Evaluates the comparator a >= b; returns 1 if true, otherwise 0
    pub fn greater_than_eq<L, CS>(a: L, b: L, cs: &mut CS) -> Variable
    where
        L: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    {
        GreaterThanEqZeroGadget::<D>::greater_than_zero(a.into() - b.into(), cs)
    }

    /// Constrains the values to satisfy a >= b
    pub fn constrain_greater_than_eq<L, CS>(a: L, b: L, cs: &mut CS)
    where
        L: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    {
        GreaterThanEqZeroGadget::<D>::constrain_greater_than_zero(a.into() - b.into(), cs);
    }
}

/// Gadget for a < b
///
/// D is the bitlength of the inputs
#[derive(Clone, Debug)]
pub struct LessThanGadget<const D: usize> {}
impl<const D: usize> LessThanGadget<D> {
    /// Compute the boolean a < b; returns 1 if true, otherwise 0
    pub fn less_than<L, CS>(a: L, b: L, cs: &mut CS) -> LinearCombination
    where
        L: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    {
        let a_geq_b = GreaterThanEqGadget::<D>::greater_than_eq(a, b, cs);
        Variable::One() - a_geq_b
    }

    /// Constrain a to be less than b
    pub fn constrain_less_than<L, CS>(a: L, b: L, cs: &mut CS)
    where
        L: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    {
        let lt_result = Self::less_than(a, b, cs);
        cs.constrain(Variable::One() - lt_result);
    }
}

/// A multiprover variant of the EqGadget
pub struct MultiproverEqGadget<'a> {
    /// Phantom
    _phantom: &'a PhantomData<()>,
}

impl<'a> MultiproverEqGadget<'a> {
    /// Constraint two values to be equal
    pub fn constrain_eq<L1, L2, V1, V2, CS>(a: V1, b: V2, cs: &mut CS)
    where
        L1: MpcLinearCombinationLike,
        L2: MpcLinearCombinationLike,
        V1: MultiproverCircuitVariableType<L1>,
        V2: MultiproverCircuitVariableType<L2>,
        CS: MpcRandomizableConstraintSystem<'a>,
    {
        let a_vars = a.to_mpc_vars();
        let b_vars = b.to_mpc_vars();
        assert_eq!(
            a_vars.len(),
            b_vars.len(),
            "a and b must have the same length"
        );

        for (a_var, b_var) in a_vars.into_iter().zip(b_vars.into_iter()) {
            cs.constrain(a_var.into() - b_var.into());
        }
    }
}

/// A multiprover variant of the GreaterThanEqGadget
///
/// `D` is the bitlength of the input values
pub struct MultiproverGreaterThanEqGadget<'a, const D: usize> {
    /// Phantom
    _phantom: &'a PhantomData<()>,
}

impl<'a, const D: usize> MultiproverGreaterThanEqGadget<'a, D> {
    /// Constrain the relation a >= b
    pub fn constrain_greater_than_eq<L, CS>(
        a: L,
        b: L,
        fabric: MpcFabric,
        cs: &mut CS,
    ) -> Result<(), ProverError>
    where
        L: MpcLinearCombinationLike,
        CS: MpcRandomizableConstraintSystem<'a>,
    {
        MultiproverGreaterThanEqZeroGadget::<'a, D>::constrain_greater_than_zero(
            a.into() - b.into(),
            fabric,
            cs,
        )
    }
}

#[cfg(test)]
mod comparators_test {
    use std::{cmp, ops::Neg};

    use circuit_types::traits::CircuitBaseType;
    use merlin::HashChainTranscript as Transcript;
    use mpc_bulletproof::{
        r1cs::{ConstraintSystem, Prover},
        PedersenGens,
    };
    use mpc_stark::algebra::scalar::Scalar;
    use rand::{thread_rng, RngCore};

    use super::{EqZeroGadget, GreaterThanEqGadget, GreaterThanEqZeroGadget};

    /// Test the equal zero gadget
    #[test]
    fn test_eq_zero() {
        // Build a constraint system
        let pc_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        // First tests with a non-zero value
        let mut rng = thread_rng();
        let val = Scalar::random(&mut rng).commit_public(&mut prover);

        let res = EqZeroGadget::eq_zero(val, &mut prover);
        assert_eq!(Scalar::zero(), prover.eval(&res.into()));

        // Now test with the zero value
        let val = Scalar::zero().commit_public(&mut prover);
        let res = EqZeroGadget::eq_zero(val, &mut prover);

        assert_eq!(Scalar::one(), prover.eval(&res.into()));
    }

    /// Test the greater than zero constraint
    #[test]
    fn test_greater_than_zero() {
        let mut rng = thread_rng();
        let pc_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        // Test first with a positive value
        let value1 = Scalar::from(rng.next_u64()).commit_public(&mut prover);
        let res = GreaterThanEqZeroGadget::<64 /* bits */>::greater_than_zero(value1, &mut prover);
        assert_eq!(Scalar::one(), prover.eval(&res.into()));

        // Test with a negative value
        let value2 = Scalar::from(rng.next_u64())
            .neg()
            .commit_public(&mut prover);
        let res = GreaterThanEqZeroGadget::<64 /* bits */>::greater_than_zero(value2, &mut prover);
        assert_eq!(Scalar::zero(), prover.eval(&res.into()));
    }

    /// Test the greater than or equal to constraint
    #[test]
    fn test_greater_than_eq() {
        let mut rng = thread_rng();
        let pc_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        let a = rng.next_u64();
        let b = rng.next_u64();

        let max = Scalar::from(cmp::max(a, b)).commit_public(&mut prover);
        let min = Scalar::from(cmp::min(a, b)).commit_public(&mut prover);

        // Test with a > b = false
        let res = GreaterThanEqGadget::<64 /* bits */>::greater_than_eq(min, max, &mut prover);
        assert_eq!(Scalar::zero(), prover.eval(&res.into()));

        // Test with equal values
        let res = GreaterThanEqGadget::<64 /* bits */>::greater_than_eq(min, min, &mut prover);
        assert_eq!(Scalar::one(), prover.eval(&res.into()));

        // Test with a > b = true
        let res = GreaterThanEqGadget::<64 /* bits */>::greater_than_eq(max, min, &mut prover);
        assert_eq!(Scalar::one(), prover.eval(&res.into()));
    }
}
