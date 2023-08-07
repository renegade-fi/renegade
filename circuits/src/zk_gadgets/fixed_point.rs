//! Defines gadgets on fixed point types

use std::marker::PhantomData;

use circuit_types::{
    errors::ProverError,
    fixed_point::{
        AuthenticatedFixedPointVar, FixedPointVar, DEFAULT_FP_PRECISION, TWO_TO_M_SCALAR,
    },
    traits::{LinearCombinationLike, MpcLinearCombinationLike},
};
use mpc_bulletproof::{
    r1cs::{LinearCombination, RandomizableConstraintSystem, Variable},
    r1cs_mpc::{MpcLinearCombination, MpcRandomizableConstraintSystem, MpcVariable},
};
use mpc_stark::{algebra::scalar::Scalar, MpcFabric};

use super::{
    arithmetic::DivRemGadget,
    comparators::{EqGadget, GreaterThanEqGadget, MultiproverGreaterThanEqGadget},
};

/// Performs fixed point operations on a single-prover circuit
pub struct FixedPointGadget<CS: RandomizableConstraintSystem>(PhantomData<CS>);
impl<CS: RandomizableConstraintSystem> FixedPointGadget<CS> {
    // === Helpers === //

    /// Shifts an integer to the left by the fixed point precision
    /// and returns the value as an integer
    fn shift_integer(val: Variable) -> FixedPointVar<LinearCombination> {
        FixedPointVar {
            repr: *TWO_TO_M_SCALAR * val,
        }
    }

    // === Equality === //

    /// Constrain a fixed point variable to equal an integer
    pub fn constrain_equal_integer<L: LinearCombinationLike>(
        lhs: FixedPointVar<L>,
        rhs: Variable,
        cs: &mut CS,
    ) {
        let fixed_point_repr = Self::shift_integer(rhs);
        EqGadget::constrain_eq(lhs, fixed_point_repr, cs);
    }

    /// Return a boolean indicating whether a fixed point and integer are equal
    ///
    /// 1 represents true, 0 is false
    pub fn equal_integer<L: LinearCombinationLike>(
        lhs: FixedPointVar<L>,
        rhs: Variable,
        cs: &mut CS,
    ) -> Variable {
        let fixed_point_repr = Self::shift_integer(rhs);
        EqGadget::eq(lhs, fixed_point_repr, cs)
    }

    /// Constrain a fixed point variable to be equal to the given integer
    /// when ignoring the fractional part
    pub fn constrain_equal_integer_ignore_fraction<L: LinearCombinationLike>(
        lhs: FixedPointVar<L>,
        rhs: Variable,
        cs: &mut CS,
    ) {
        // Shift the integer and take the difference
        let shifted_rhs = *TWO_TO_M_SCALAR * rhs;
        let diff = lhs.repr.into() - shifted_rhs;

        // Constrain the difference to be less than the precision on the fixed point,
        // This is effectively the same as constraining the difference to have an integral
        // component of zero
        GreaterThanEqGadget::<DEFAULT_FP_PRECISION>::constrain_greater_than_eq(
            LinearCombination::from(*TWO_TO_M_SCALAR - Scalar::one()),
            diff,
            cs,
        );
    }

    // === Arithmetic Ops === //

    /// Computes the closest integral value less than the given fixed point variable and
    /// constraints this value to be correctly computed.
    ///
    /// Returns the integer representation directly
    pub fn floor<L: LinearCombinationLike>(val: FixedPointVar<L>, cs: &mut CS) -> Variable {
        // Floor div by the scaling factor
        let (div, _) = DivRemGadget::<DEFAULT_FP_PRECISION>::div_rem(
            val.repr.into(),
            *TWO_TO_M_SCALAR * Variable::One(),
            cs,
        );

        div
    }
}

/// Performs fixed point operations on a multiprover circuit
pub struct MultiproverFixedPointGadget<'a>(&'a PhantomData<()>);
impl<'a> MultiproverFixedPointGadget<'a> {
    // === Equality === //

    /// Constrain a fixed point variable to equal a native field element
    pub fn constrain_equal_integer<L, CS>(
        lhs: &AuthenticatedFixedPointVar<L>,
        rhs: &MpcVariable,
        cs: &mut CS,
    ) where
        L: MpcLinearCombinationLike,
        CS: MpcRandomizableConstraintSystem,
    {
        // Shift the integer
        let shifted_rhs = *TWO_TO_M_SCALAR * rhs;
        cs.constrain(lhs.repr.clone().into() - shifted_rhs);
    }

    /// Constrain a fixed point variable to be equal to the given integer
    /// when ignoring the fractional part
    pub fn constrain_equal_integer_ignore_fraction<L, CS>(
        lhs: &AuthenticatedFixedPointVar<L>,
        rhs: &MpcVariable,
        fabric: MpcFabric,
        cs: &mut CS,
    ) -> Result<(), ProverError>
    where
        L: MpcLinearCombinationLike,
        CS: MpcRandomizableConstraintSystem,
    {
        // Shift the integer and take the difference
        let shifted_rhs = *TWO_TO_M_SCALAR * rhs;
        let diff = lhs.repr.clone().into() - shifted_rhs;

        // Constrain the difference to be less than the precision on the fixed point,
        // This is effectively the same as constraining the difference to have an integral
        // component of zero
        let shifted_precision =
            MpcLinearCombination::from_scalar(*TWO_TO_M_SCALAR - Scalar::one(), fabric.clone());
        MultiproverGreaterThanEqGadget::<'_, DEFAULT_FP_PRECISION>::constrain_greater_than_eq(
            shifted_precision,
            diff,
            fabric,
            cs,
        )
    }
}
