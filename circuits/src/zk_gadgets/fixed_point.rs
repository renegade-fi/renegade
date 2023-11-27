//! Defines gadgets on fixed point types

use ark_ff::One;
use circuit_types::{
    fixed_point::{FixedPointVar, DEFAULT_FP_PRECISION, TWO_TO_M_SCALAR},
    Fabric, MpcPlonkCircuit, PlonkCircuit,
};
use constants::ScalarField;
use mpc_relation::{errors::CircuitError, traits::Circuit, BoolVar, Variable};

use super::{
    arithmetic::DivRemGadget,
    comparators::{EqGadget, GreaterThanEqZeroGadget, MultiproverGreaterThanEqZeroGadget},
};

/// Performs fixed point operations on a single-prover circuit
pub struct FixedPointGadget;
impl FixedPointGadget {
    // === Helpers === //

    /// Shifts an integer to the left by the fixed point precision
    /// and returns the value as a fixed point value
    pub fn integer_to_fixed_point<C: Circuit<ScalarField>>(
        val: Variable,
        cs: &mut C,
    ) -> Result<FixedPointVar, CircuitError> {
        let repr = cs.mul_constant(val, &*TWO_TO_M_SCALAR)?;
        Ok(FixedPointVar { repr })
    }

    // === Equality === //

    /// Constrain a fixed point variable to equal an integer
    pub fn constrain_equal_integer<C: Circuit<ScalarField>>(
        lhs: FixedPointVar,
        rhs: Variable,
        cs: &mut C,
    ) -> Result<(), CircuitError> {
        let fixed_point_repr = Self::integer_to_fixed_point(rhs, cs)?;
        EqGadget::constrain_eq(&lhs, &fixed_point_repr, cs)?;

        Ok(())
    }

    /// Return a boolean indicating whether a fixed point and integer are equal
    ///
    /// 1 represents true, 0 is false
    pub fn equal_integer(
        lhs: FixedPointVar,
        rhs: Variable,
        cs: &mut PlonkCircuit,
    ) -> Result<BoolVar, CircuitError> {
        let fixed_point_repr = Self::integer_to_fixed_point(rhs, cs)?;
        EqGadget::eq(&lhs, &fixed_point_repr, cs)
    }

    /// Constrain a fixed point variable to be equal to the given integer
    /// when ignoring the fractional part
    pub fn constrain_equal_integer_ignore_fraction(
        lhs: FixedPointVar,
        rhs: Variable,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Shift the integer and take the difference
        let zero_var = cs.zero();
        let one_var = cs.one();
        let one = ScalarField::one();

        let lhs_minus_rhs =
            cs.lc(&[lhs.repr, rhs, zero_var, zero_var], &[one, -*TWO_TO_M_SCALAR, one, one])?;

        // Constrain the difference to be less than the precision on the fixed point,
        // This is effectively the same as constraining the difference to have an
        // integral component of zero
        // 2^m - (lhs - rhs) > 0
        let diff = cs.lc(
            &[one_var, lhs_minus_rhs, zero_var, zero_var],
            &[*TWO_TO_M_SCALAR, -one, one, one],
        )?;
        GreaterThanEqZeroGadget::<DEFAULT_FP_PRECISION>::constrain_greater_than_zero(diff, cs)
    }

    // === Arithmetic Ops === //

    /// Computes the closest integral value less than the given fixed point
    /// variable and constraints this value to be correctly computed.
    ///
    /// Returns the integer representation directly
    pub fn floor(val: FixedPointVar, cs: &mut PlonkCircuit) -> Result<Variable, CircuitError> {
        // Floor div by the scaling factor
        let divisor = cs.mul_constant(cs.one(), &*TWO_TO_M_SCALAR).unwrap();
        let (div, _) = DivRemGadget::<DEFAULT_FP_PRECISION>::div_rem(val.repr, divisor, cs)?;

        Ok(div)
    }
}

/// Performs fixed point operations on a multiprover circuit
pub struct MultiproverFixedPointGadget;
impl MultiproverFixedPointGadget {
    // === Equality === //

    /// Constrain a fixed point variable to be equal to the given integer
    /// when ignoring the fractional part
    pub fn constrain_equal_integer_ignore_fraction(
        lhs: FixedPointVar,
        rhs: Variable,
        fabric: &Fabric,
        cs: &mut MpcPlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Shift the rhs and subtract from the lhs
        let zero_var = cs.zero();
        let one_var = cs.one();
        let one = ScalarField::one();

        let lhs_minus_rhs =
            cs.lc(&[lhs.repr, rhs, zero_var, zero_var], &[one, -*TWO_TO_M_SCALAR, one, one])?;

        // Constrain the difference to be less than the precision on the fixed point,
        // This is effectively the same as constraining the difference to have an
        // integral component of zero
        let diff = cs.lc(
            &[one_var, lhs_minus_rhs, zero_var, zero_var],
            &[*TWO_TO_M_SCALAR, -one, one, one],
        )?;

        MultiproverGreaterThanEqZeroGadget::<DEFAULT_FP_PRECISION>::constrain_greater_than_zero(
            diff, fabric, cs,
        )
    }
}

#[cfg(test)]
mod test {
    use ark_mpc::PARTY0;
    use circuit_types::{
        fixed_point::FixedPoint,
        traits::{CircuitBaseType, MpcBaseType, MultiproverCircuitBaseType},
        MpcPlonkCircuit, PlonkCircuit,
    };
    use mpc_relation::traits::Circuit;
    use rand::{thread_rng, Rng};
    use test_helpers::mpc_network::execute_mock_mpc;

    use crate::zk_gadgets::fixed_point::MultiproverFixedPointGadget;

    use super::FixedPointGadget;

    /// Test the equality methods
    #[test]
    fn test_equality() {
        let mut rng = thread_rng();
        let fp1: f64 = rng.gen();
        let fp_floor = fp1.floor() as u64;
        let int: u64 = rng.gen();

        // Allocate the values in a constraint system
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let fp_var1 = FixedPoint::from_f64_round_down(fp1).create_witness(&mut cs);
        let floor_var = fp_floor.create_witness(&mut cs);

        let int_var = int.create_witness(&mut cs);
        let int_fp = FixedPoint::from_integer(int).create_witness(&mut cs);

        // int_fp == int_var
        let res1 = FixedPointGadget::equal_integer(int_fp, int_var, &mut cs).unwrap();
        cs.enforce_true(res1).unwrap();

        // fp1 != floor(fp1)
        let res2 = FixedPointGadget::equal_integer(fp_var1, floor_var, &mut cs).unwrap();
        cs.enforce_false(res2).unwrap();

        // fp1 == floor(fp1), when ignoring the fractional part
        FixedPointGadget::constrain_equal_integer_ignore_fraction(fp_var1, floor_var, &mut cs)
            .unwrap();

        // Validate constraints
        assert!(cs.check_circuit_satisfiability(&[]).is_ok());
    }

    /// Tests the floor method
    #[test]
    fn test_floor() {
        let mut rng = thread_rng();
        let fp1: f64 = rng.gen();
        let floor = fp1.floor() as u64;

        // Compute the floor in-circuit
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let fp_var1 = FixedPoint::from_f64_round_down(fp1).create_witness(&mut cs);
        let floor_var = floor.create_witness(&mut cs);

        let floor_res = FixedPointGadget::floor(fp_var1, &mut cs).unwrap();
        cs.enforce_equal(floor_res, floor_var).unwrap();

        // Validate constraints
        assert!(cs.check_circuit_satisfiability(&[]).is_ok());
    }

    /// Tests the multiprover equality method
    #[tokio::test]
    async fn test_multiprover_integer_equality() {
        let mut rng = thread_rng();
        let fp1: f64 = rng.gen();
        let fp_floor = fp1.floor() as u64;
        let int: u64 = rng.gen();

        let (res, _) = execute_mock_mpc(move |fabric| async move {
            let mut cs = MpcPlonkCircuit::new(fabric.clone());

            let fp_var = FixedPoint::from_f64_round_down(fp1)
                .allocate(PARTY0, &fabric)
                .create_shared_witness(&mut cs);
            let floor_var = fp_floor.allocate(PARTY0, &fabric).create_shared_witness(&mut cs);
            let int_var = int.allocate(PARTY0, &fabric).create_shared_witness(&mut cs);

            // fp1 == floor(fp1), when ignoring the fractional part
            MultiproverFixedPointGadget::constrain_equal_integer_ignore_fraction(
                fp_var, floor_var, &fabric, &mut cs,
            )
            .unwrap();

            let res = cs.check_circuit_satisfiability(&[]).is_ok();

            // fp1 != int
            MultiproverFixedPointGadget::constrain_equal_integer_ignore_fraction(
                fp_var, int_var, &fabric, &mut cs,
            )
            .unwrap();

            res & cs.check_circuit_satisfiability(&[]).is_err()
        })
        .await;

        assert!(res);
    }
}
