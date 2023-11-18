//! Groups ZK gadgets used as arithmetic primitives in more complicated
//! computations

use ark_ff::One;
use circuit_types::traits::{CircuitBaseType, CircuitVarType};
use circuit_types::PlonkCircuit;
use constants::ScalarField;
use mpc_relation::errors::CircuitError;
use mpc_relation::traits::Circuit;
use mpc_relation::Variable;
use renegade_crypto::fields::{biguint_to_scalar, scalar_to_biguint};

use num_integer::Integer;

use super::comparators::LessThanGadget;

// -------------------------
// | Single Prover Gadgets |
// -------------------------

/// A div-rem gadget which for inputs `a`, `b` returns
/// values `q`, `r` such that a = bq + r and r < b
///
/// The generic constant `D` represents the bitlength of the input `b`
#[derive(Clone, Debug)]
pub struct DivRemGadget<const D: usize> {}
impl<const D: usize> DivRemGadget<D> {
    /// Return (q, r) such that a = bq + r and r < b
    pub fn div_rem(
        a: Variable,
        b: Variable,
        cs: &mut PlonkCircuit,
    ) -> Result<(Variable, Variable), CircuitError> {
        let a_bigint = scalar_to_biguint(&a.eval(cs));
        let b_bigint = scalar_to_biguint(&b.eval(cs));

        // Compute the divrem outside of the circuit
        let (q, r) = a_bigint.div_rem(&b_bigint);

        let q_var = biguint_to_scalar(&q).create_witness(cs);
        let r_var = biguint_to_scalar(&r).create_witness(cs);

        // Constrain a == bq + r
        let one_var = cs.one();
        let one = ScalarField::one();
        cs.mul_add_gate(&[b, q_var, r_var, one_var, a], &[one, one])?;

        // Constraint r < b
        LessThanGadget::<D>::constrain_less_than(r_var, b, cs)?;

        Ok((q_var, r_var))
    }
}

/// A gadget to compute exponentiation: x^\alpha
pub struct ExpGadget {}
impl ExpGadget {
    /// Computes a representation of x^\alpha
    pub fn exp<C: Circuit<ScalarField>>(
        x: Variable,
        alpha: u64,
        cs: &mut C,
    ) -> Result<Variable, CircuitError> {
        if alpha == 0 {
            Ok(cs.one())
        } else if alpha == 1 {
            Ok(x)
        } else if alpha % 2 == 0 {
            let recursive_result = ExpGadget::exp(x, alpha / 2, cs)?;
            cs.mul(recursive_result, recursive_result)
        } else {
            let recursive_result = ExpGadget::exp(x, (alpha - 1) / 2, cs)?;
            let double = cs.mul(recursive_result, recursive_result)?;
            cs.mul(double, x)
        }
    }
}

#[cfg(test)]
mod arithmetic_tests {
    use circuit_types::{traits::CircuitBaseType, PlonkCircuit};
    use constants::Scalar;
    use mpc_relation::traits::Circuit;
    use num_bigint::BigUint;
    use num_integer::Integer;
    use rand::{thread_rng, RngCore};
    use renegade_crypto::fields::biguint_to_scalar;

    use super::{DivRemGadget, ExpGadget};

    /// Tests the div_rem gadget
    #[test]
    fn test_div_rem() {
        // Sample random inputs
        let mut rng = thread_rng();
        let random_dividend = BigUint::from(rng.next_u32());
        let random_divisor = BigUint::from(rng.next_u32());

        let (expected_q, expected_r) = random_dividend.div_rem(&random_divisor);
        let expected_q = biguint_to_scalar(&expected_q);
        let expected_r = biguint_to_scalar(&expected_r);

        // Build a constraint system
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let expected_q_var = expected_q.create_public_var(&mut cs);
        let expected_r_var = expected_r.create_public_var(&mut cs);

        // Allocate the inputs in the constraint system
        let dividend_var = biguint_to_scalar(&random_dividend).create_witness(&mut cs);
        let divisor_var = biguint_to_scalar(&random_divisor).create_witness(&mut cs);

        let (q_res, r_res) =
            DivRemGadget::<32 /* bitlength */>::div_rem(dividend_var, divisor_var, &mut cs)
                .unwrap();

        cs.enforce_equal(expected_q_var, q_res).unwrap();
        cs.enforce_equal(expected_r_var, r_res).unwrap();

        assert!(cs
            .check_circuit_satisfiability(&[expected_q.inner(), expected_r.inner()])
            .is_ok())
    }

    /// Tests the exp gadget
    #[test]
    fn test_exp() {
        let mut rng = thread_rng();
        let base = Scalar::random(&mut rng);
        let exp = rng.next_u64();

        let expected = base.pow(exp);

        // Compute the result in-circuit
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let base_var = base.create_witness(&mut cs);
        let expected_var = expected.create_public_var(&mut cs);

        let result = ExpGadget::exp(base_var, exp, &mut cs).unwrap();
        cs.enforce_equal(result, expected_var).unwrap();

        assert!(cs.check_circuit_satisfiability(&[expected.inner()]).is_ok());
    }
}
