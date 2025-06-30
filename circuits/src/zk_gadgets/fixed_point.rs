//! Defines gadgets on fixed point types

use ark_ff::One;
use circuit_types::{
    Fabric, MpcPlonkCircuit, PlonkCircuit,
    fixed_point::{DEFAULT_FP_PRECISION, FixedPointVar, TWO_TO_M_SCALAR},
};
use constants::ScalarField;
use mpc_relation::{BoolVar, Variable, errors::CircuitError, traits::Circuit};

use super::{
    arithmetic::DivRemGadget,
    bits::{BitRangeGadget, MultiproverBitRangeGadget},
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
        // (2^m - 1) - (lhs - rhs) > 0
        let diff = cs.lc(
            &[one_var, lhs_minus_rhs, zero_var, zero_var],
            &[(*TWO_TO_M_SCALAR - ScalarField::one()), -one, one, one],
        )?;

        const NUM_BITS: usize = DEFAULT_FP_PRECISION + 1;
        GreaterThanEqZeroGadget::constrain_greater_than_eq_zero(diff, NUM_BITS, cs)
    }

    /// Constrain an integer to be equal to the floor of a fixed point value
    pub fn constrain_equal_floor(
        fp: FixedPointVar,
        integer: Variable,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let one = ScalarField::one();
        let zero_var = cs.zero();

        // fp - (2^m * integer)
        let lhs_minus_rhs =
            cs.lc(&[fp.repr, integer, zero_var, zero_var], &[one, -*TWO_TO_M_SCALAR, one, one])?;

        // This diff must be a positive value representable in at most M bits
        BitRangeGadget::constrain_bit_range(lhs_minus_rhs, DEFAULT_FP_PRECISION, cs)
    }

    // === Arithmetic Ops === //

    /// Computes the closest integral value less than the given fixed point
    /// variable and constraints this value to be correctly computed.
    ///
    /// Returns the integer representation directly
    pub fn floor(val: FixedPointVar, cs: &mut PlonkCircuit) -> Result<Variable, CircuitError> {
        // Floor div by the scaling factor
        const NUM_BITS: usize = DEFAULT_FP_PRECISION + 1;
        let divisor = cs.mul_constant(cs.one(), &*TWO_TO_M_SCALAR).unwrap();
        let (div, _) = DivRemGadget::div_rem(val.repr, divisor, NUM_BITS, cs)?;

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
            &[(*TWO_TO_M_SCALAR - ScalarField::one()), -one, one, one],
        )?;

        const NUM_BITS: usize = DEFAULT_FP_PRECISION + 1;
        MultiproverGreaterThanEqZeroGadget::constrain_greater_than_eq_zero(
            diff, NUM_BITS, fabric, cs,
        )
    }

    /// Constrain a fixed point variable to equal an integral variable when
    /// floored
    pub fn constrain_equal_floor(
        fp: FixedPointVar,
        integer: Variable,
        fabric: &Fabric,
        cs: &mut MpcPlonkCircuit,
    ) -> Result<(), CircuitError> {
        let zero_var = cs.zero();
        let one = ScalarField::one();

        let lhs_minus_rhs =
            cs.lc(&[fp.repr, integer, zero_var, zero_var], &[one, -*TWO_TO_M_SCALAR, one, one])?;
        MultiproverBitRangeGadget::constrain_bit_range(
            lhs_minus_rhs,
            DEFAULT_FP_PRECISION,
            fabric,
            cs,
        )
    }
}

#[cfg(test)]
mod test {
    use ark_mpc::PARTY0;
    use circuit_types::{
        MpcPlonkCircuit, PlonkCircuit,
        fixed_point::FixedPoint,
        traits::{CircuitBaseType, MpcBaseType, MultiproverCircuitBaseType},
    };
    use constants::Scalar;
    use mpc_relation::traits::Circuit;
    use rand::{Rng, thread_rng};
    use test_helpers::mpc_network::execute_mock_mpc;

    use crate::zk_gadgets::fixed_point::MultiproverFixedPointGadget;

    use super::FixedPointGadget;

    // -----------
    // | Helpers |
    // -----------

    /// Generate a random fixed point value
    fn random_fixed_point() -> FixedPoint {
        let mut rng = thread_rng();
        FixedPoint::from_repr(Scalar::random(&mut rng))
    }

    /// A helper to test the floor method
    ///
    /// Returns whether the constraints are satisfied
    fn floor_test_helper(integer: Scalar, fp: FixedPoint) -> bool {
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let fp_var = fp.create_witness(&mut cs);
        let floor_var = integer.create_witness(&mut cs);
        FixedPointGadget::constrain_equal_floor(fp_var, floor_var, &mut cs).unwrap();

        cs.check_circuit_satisfiability(&[]).is_ok()
    }

    /// A helper to test the floor method in a multiprover context
    async fn floor_test_helper_mpc(fp: FixedPoint, int: Scalar) -> bool {
        let (valid, _) = execute_mock_mpc(move |fabric| async move {
            let mut cs = MpcPlonkCircuit::new(fabric.clone());
            let fp_var = fp.allocate(PARTY0, &fabric).create_shared_witness(&mut cs);
            let int_var = int.allocate(PARTY0, &fabric).create_shared_witness(&mut cs);
            MultiproverFixedPointGadget::constrain_equal_floor(fp_var, int_var, &fabric, &mut cs)
                .unwrap();

            cs.check_circuit_satisfiability(&[]).is_ok()
        })
        .await;

        valid
    }

    // ---------
    // | Tests |
    // ---------

    /// Test the equality methods
    #[test]
    fn test_equality() {
        let mut rng = thread_rng();
        let fp1: f64 = rng.r#gen();
        let fp_floor = fp1.floor() as u64;
        let fp_ceil = fp1.ceil() as u64;
        let int: u64 = rng.r#gen();

        // Allocate the values in a constraint system
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let fp_var1 = FixedPoint::from_f64_round_down(fp1).create_witness(&mut cs);
        let floor_var = fp_floor.create_witness(&mut cs);
        let ceil_var = fp_ceil.create_witness(&mut cs);

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

        // fp1 == ceil(fp1) when ignoring the fractional part
        FixedPointGadget::constrain_equal_integer_ignore_fraction(fp_var1, ceil_var, &mut cs)
            .unwrap();

        // int_fp == int_var when ignoring the fractional part
        FixedPointGadget::constrain_equal_integer_ignore_fraction(int_fp, int_var, &mut cs)
            .unwrap();

        // Validate constraints -- all should be true at this point
        assert!(cs.check_circuit_satisfiability(&[]).is_ok());

        // int_fp + 1 != int when ignoring the fractional part
        let int_fp_plus_one = FixedPoint::from_integer(int + 1).create_witness(&mut cs);
        FixedPointGadget::constrain_equal_integer_ignore_fraction(
            int_fp_plus_one,
            int_var,
            &mut cs,
        )
        .unwrap();

        // Validate constraints -- should now fail
        assert!(cs.check_circuit_satisfiability(&[]).is_err());
    }

    /// Tests the floor method
    #[test]
    fn test_floor() {
        let mut rng = thread_rng();
        let fp1: f64 = rng.r#gen();
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

    /// Tests the integer floor equality method
    ///
    /// Tests both a single prover and multiprover circuit
    #[tokio::test]
    async fn test_integer_floor_equality() {
        // Test data
        let mut rng = thread_rng();
        let test_fp = random_fixed_point();
        let test_int = test_fp.floor();
        let test_u64 = rng.r#gen::<u64>();

        let mut test_cases = vec![];
        /// A test case for the floor method
        struct TestCase {
            fp: FixedPoint,
            int: Scalar,
            valid: bool,
        }

        // Case 1: fp == int -- Valid
        test_cases.push(TestCase {
            fp: FixedPoint::from_integer(test_u64),
            int: test_u64.into(),
            valid: true,
        });

        // Case 2: floor(fp) == int -- Valid
        test_cases.push(TestCase { fp: test_fp, int: test_int, valid: true });

        // Case 3: ceil(fp) == int -- Invalid
        test_cases.push(TestCase { fp: test_fp, int: test_int + Scalar::one(), valid: false });

        // Case 4: fp = int + 1 -- Invalid (smallest invalid fp)
        test_cases.push(TestCase {
            fp: FixedPoint::from_integer(test_u64 + 1),
            int: test_u64.into(),
            valid: false,
        });

        // Case 5: fp = int + 1 - \epsilon -- Valid (largest valid fp)
        let mut fp = FixedPoint::from_integer(test_u64 + 1);
        fp.repr -= Scalar::one();
        test_cases.push(TestCase { fp, int: test_u64.into(), valid: true });

        // Case 6: fp = int + \epsilon -- Valid (smallest valid fp)
        let mut fp = FixedPoint::from_integer(test_u64);
        fp.repr += Scalar::one();
        test_cases.push(TestCase { fp, int: test_u64.into(), valid: true });

        // Case 7: fp = int - \epsilon -- Invalid (largest invalid fp)
        let mut fp = FixedPoint::from_integer(test_u64);
        fp.repr -= Scalar::one();
        test_cases.push(TestCase { fp, int: test_u64.into(), valid: false });

        // Case 8: random fp and random floor value -- Invalid
        let fp = random_fixed_point();
        let int = Scalar::random(&mut rng);
        test_cases.push(TestCase { fp, int, valid: false });

        // Run the tests
        for test in test_cases {
            assert!(floor_test_helper(test.int, test.fp) == test.valid);
            assert!(floor_test_helper_mpc(test.fp, test.int).await == test.valid);
        }
    }

    /// Tests the multiprover equality method
    #[tokio::test]
    async fn test_multiprover_integer_equality() {
        let mut rng = thread_rng();
        let fp1: f64 = rng.r#gen();
        let fp_floor = fp1.floor() as u64;
        let fp_ceil = fp1.ceil() as u64;
        let int: u64 = rng.r#gen();

        let (res, _) = execute_mock_mpc(move |fabric| async move {
            let mut cs = MpcPlonkCircuit::new(fabric.clone());

            let fp_var = FixedPoint::from_f64_round_down(fp1)
                .allocate(PARTY0, &fabric)
                .create_shared_witness(&mut cs);
            let floor_var = fp_floor.allocate(PARTY0, &fabric).create_shared_witness(&mut cs);
            let ceil_var = fp_ceil.allocate(PARTY0, &fabric).create_shared_witness(&mut cs);
            let int_var = int.allocate(PARTY0, &fabric).create_shared_witness(&mut cs);

            // fp1 == floor(fp1), when ignoring the fractional part
            MultiproverFixedPointGadget::constrain_equal_integer_ignore_fraction(
                fp_var, floor_var, &fabric, &mut cs,
            )
            .unwrap();

            // fp1 == ceil(fp), when ignoring the fractional part
            MultiproverFixedPointGadget::constrain_equal_integer_ignore_fraction(
                fp_var, ceil_var, &fabric, &mut cs,
            )
            .unwrap();

            // int_fp == int_var when ignoring the fractional part
            let int_fp = FixedPoint::from_integer(int)
                .allocate(PARTY0, &fabric)
                .create_shared_witness(&mut cs);
            MultiproverFixedPointGadget::constrain_equal_integer_ignore_fraction(
                int_fp, int_var, &fabric, &mut cs,
            )
            .unwrap();

            let mut res = cs.check_circuit_satisfiability(&[]).is_ok();

            // int_fp + 1 != int when ignoring the fractional part
            let int_fp_plus_one = FixedPoint::from_integer(int + 1)
                .allocate(PARTY0, &fabric)
                .create_shared_witness(&mut cs);
            MultiproverFixedPointGadget::constrain_equal_integer_ignore_fraction(
                int_fp_plus_one,
                int_var,
                &fabric,
                &mut cs,
            )
            .unwrap();

            res &= cs.check_circuit_satisfiability(&[]).is_err();

            // fp1 != int
            // Use a new circuit as the constraints on the old one are already unsatisfied
            let mut cs = MpcPlonkCircuit::new(fabric.clone());
            let fp_var = FixedPoint::from_f64_round_down(fp1)
                .allocate(PARTY0, &fabric)
                .create_shared_witness(&mut cs);
            let int_var = int.allocate(PARTY0, &fabric).create_shared_witness(&mut cs);

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
