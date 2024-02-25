//! Groups gadgets for binary comparison operators
//!
//! Some gadgets are implemented for both single-prover and multi-prover
//! however, some gadgets are only implemented for single-prover circuits.
//! This is done when the gadget is inefficient and unneeded in an MPC circuit.
//! Or, for example with `EqZero` gadget, if the gadget would leak privacy.

use ark_ff::{Field, One, Zero};
use ark_mpc::ResultValue;
use circuit_types::{
    traits::{CircuitBaseType, CircuitVarType, MultiproverCircuitBaseType},
    Fabric, MpcPlonkCircuit, PlonkCircuit,
};
use constants::{AuthenticatedScalar, Scalar, ScalarField, ScalarResult};
use itertools::Itertools;
use mpc_relation::{errors::CircuitError, traits::Circuit, BoolVar, Variable};

use super::bits::{MultiproverToBitsGadget, ToBitsGadget};

// ------------------------
// | Singleprover Gadgets |
// ------------------------

/// A gadget that returns whether a value is equal to zero
#[derive(Clone, Debug)]
pub struct EqZeroGadget {}
impl EqZeroGadget {
    /// Computes whether the given input is equal to zero
    ///
    /// Relies on the fact that modulo a prime field, all elements (except zero)
    /// have a valid multiplicative inverse
    pub fn eq_zero_var(val: Variable, cs: &mut PlonkCircuit) -> Result<BoolVar, CircuitError> {
        // Compute the inverse of the value outside the circuit then allocate it in the
        // circuit
        let val_eval = cs.witness(val).unwrap();

        let (is_zero, inverse) = if val_eval == ScalarField::zero() {
            (Scalar::one(), Scalar::zero())
        } else {
            (Scalar::zero(), Scalar::new(val_eval.inverse().unwrap()))
        };

        let is_zero_var = is_zero.create_witness(cs);
        let inv_var = inverse.create_witness(cs);

        // Constrain `is_zero == 1 - val * inv`
        //
        // If the value is zero, then the right hand side will always be one, so the
        // circuit is well constrained
        //
        // If the value is non-zero (and inv is correctly assigned), then the right hand
        // side will be zero. The only check left is that inv is not set to
        // zero, allowing a non-zero `val` to satisfy the constraints with `is_zero = 1`
        // This is implicitly handled in the second constraint by ensuring that the
        // input times the output is zero, which for non-zero input is only true
        // if the output is zero
        let zero_var = cs.zero();
        let one_var = cs.one();
        let one = ScalarField::one();

        cs.mul_add_gate(&[val, inv_var, one_var, one_var, is_zero_var], &[-one, one])?;
        cs.mul_gate(is_zero_var, val, zero_var)?;

        // We do not need to enforce that the result is boolean, only 0 or 1 will
        // satisfy the previous two constraints
        Ok(BoolVar::new_unchecked(is_zero_var))
    }

    /// Computes whether the given input is all zeros
    ///
    /// Decomposes the value into its components and checks if each component is
    /// zero
    pub fn eq_zero<V: CircuitVarType>(
        val: &V,
        cs: &mut PlonkCircuit,
    ) -> Result<BoolVar, CircuitError> {
        let val_vars = val.to_vars();
        EqVecGadget::eq_zero_vec(&val_vars, cs)
    }
}

/// Gadget for testing and constraining equality
#[derive(Clone, Debug)]
pub struct EqGadget {}
impl EqGadget {
    /// Computes a == b
    pub fn eq<V>(a: &V, b: &V, cs: &mut PlonkCircuit) -> Result<BoolVar, CircuitError>
    where
        V: CircuitVarType,
    {
        let a_vars = a.to_vars();
        let b_vars = b.to_vars();

        EqVecGadget::eq_vec(&a_vars, &b_vars, cs)
    }

    /// Constraints a == b
    pub fn constrain_eq<V, C>(a: &V, b: &V, cs: &mut C) -> Result<(), CircuitError>
    where
        V: CircuitVarType,
        C: Circuit<ScalarField>,
    {
        let a_vars = a.to_vars();
        let b_vars = b.to_vars();
        assert!(a_vars.len() == b_vars.len(), "a and b must have the same length");

        EqVecGadget::constrain_eq_vec(&a_vars, &b_vars, cs)
    }
}

/// Gadgets for testing or constraining the equality of vectors of variable
/// types
#[derive(Clone, Debug)]
pub struct EqVecGadget {}
impl EqVecGadget {
    /// Returns 1 if \vec{a} = \vec{b}, otherwise 0
    pub fn eq_vec<V>(a: &[V], b: &[V], cs: &mut PlonkCircuit) -> Result<BoolVar, CircuitError>
    where
        V: CircuitVarType,
    {
        assert_eq!(a.len(), b.len(), "eq_vec expects equal length vectors");
        let a_vals = a.iter().cloned().flat_map(|a_val| a_val.to_vars());
        let b_vals = b.iter().cloned().flat_map(|b_val| b_val.to_vars());

        let mut component_eq_vals = Vec::new();
        for (a_val, b_val) in a_vals.zip(b_vals) {
            let a_minus_b = cs.sub(a_val, b_val)?;
            let eq_val = EqZeroGadget::eq_zero_var(a_minus_b, cs)?;
            component_eq_vals.push(eq_val);
        }

        cs.logic_and_all(&component_eq_vals)
    }

    /// Returns 1 is \vec{a} = \vec{0}
    pub fn eq_zero_vec<V>(a: &[V], cs: &mut PlonkCircuit) -> Result<BoolVar, CircuitError>
    where
        V: CircuitVarType,
    {
        let vals = a.iter().cloned().flat_map(|a_val| a_val.to_vars());
        let mut component_eq_vals = Vec::new();
        for val in vals {
            let eq_val = EqZeroGadget::eq_zero_var(val, cs)?;
            component_eq_vals.push(eq_val);
        }

        cs.logic_and_all(&component_eq_vals)
    }

    /// Constraints the two vectors to be equal
    pub fn constrain_eq_vec<V, C>(a: &[V], b: &[V], cs: &mut C) -> Result<(), CircuitError>
    where
        V: CircuitVarType,
        C: Circuit<ScalarField>,
    {
        assert_eq!(a.len(), b.len(), "eq_vec expects equal length vectors");
        let a_vars = a.iter().cloned().flat_map(|a_val| a_val.to_vars()).collect_vec();
        let b_vars = b.iter().cloned().flat_map(|b_val| b_val.to_vars()).collect_vec();

        for (a_val, b_val) in a_vars.into_iter().zip(b_vars) {
            cs.enforce_equal(a_val, b_val)?;
        }

        Ok(())
    }
}

/// Returns a boolean representing a != b where 1 is true and 0 is false
#[derive(Debug)]
pub struct NotEqualGadget {}
impl NotEqualGadget {
    /// Computes a != b
    pub fn not_equal(
        a: Variable,
        b: Variable,
        cs: &mut PlonkCircuit,
    ) -> Result<BoolVar, CircuitError> {
        let eq = EqGadget::eq(&a, &b, cs)?;
        cs.logic_neg(eq)
    }
}

/// A gadget that enforces a value of a given bitlength is positive
///
/// The sizing parameter `D` represents the maximum bitlength of positive
/// scalars under the caller's representation
#[derive(Clone, Debug)]
pub struct GreaterThanEqZeroGadget<const D: usize> {}
impl<const D: usize> GreaterThanEqZeroGadget<D> {
    /// Evaluate the condition x >= 0; returns 1 if true, otherwise 0
    pub fn greater_than_eq_zero(
        x: Variable,
        cs: &mut PlonkCircuit,
    ) -> Result<BoolVar, CircuitError> {
        // Decompose and reconstruct the value in the given bitlength, if we can do so
        // then the value is greater than zero
        let reconstructed = ToBitsGadget::<D>::decompose_and_reconstruct(x, cs)?;
        EqGadget::eq(&reconstructed, &x, cs)
    }

    /// Constrain the value to be greater than zero
    pub fn constrain_greater_than_eq_zero(
        x: Variable,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // If we can reconstruct the value in the given bitlength, then the value is
        // greater than zero
        ToBitsGadget::<D>::to_bits(x, cs).map(|_| ())
    }
}

/// Enforces the constraint a >= b
///
/// `D` is the bitlength of the values being compared
pub struct GreaterThanEqGadget<const D: usize> {}
impl<const D: usize> GreaterThanEqGadget<D> {
    /// Evaluates the comparator a >= b; returns 1 if true, otherwise 0
    pub fn greater_than_eq(
        a: Variable,
        b: Variable,
        cs: &mut PlonkCircuit,
    ) -> Result<BoolVar, CircuitError> {
        let a_minus_b = cs.sub(a, b)?;
        GreaterThanEqZeroGadget::<D>::greater_than_eq_zero(a_minus_b, cs)
    }

    /// Constrains the values to satisfy a >= b
    pub fn constrain_greater_than_eq(
        a: Variable,
        b: Variable,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let a_minus_b = cs.sub(a, b)?;
        GreaterThanEqZeroGadget::<D>::constrain_greater_than_eq_zero(a_minus_b, cs)
    }
}

/// Gadget for a < b
///
/// D is the bitlength of the inputs
#[derive(Clone, Debug)]
pub struct LessThanGadget<const D: usize> {}
impl<const D: usize> LessThanGadget<D> {
    /// Compute the boolean a < b; returns 1 if true, otherwise 0
    pub fn less_than(
        a: Variable,
        b: Variable,
        cs: &mut PlonkCircuit,
    ) -> Result<BoolVar, CircuitError> {
        let a_geq_b = GreaterThanEqGadget::<D>::greater_than_eq(a, b, cs)?;
        cs.logic_neg(a_geq_b)
    }

    /// Constrain a to be less than b
    pub fn constrain_less_than(
        a: Variable,
        b: Variable,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let lt_result = Self::less_than(a, b, cs)?;
        cs.enforce_true(lt_result)
    }
}

// -----------------------
// | Multiprover Gadgets |
// -----------------------

/// A multiprover version of the equal gadget
pub struct MultiproverEqGadget;
impl MultiproverEqGadget {
    /// Computes whether the given input is equal to zero
    ///
    /// Warning: This requires opening the value to both parties so that they
    /// may assign a wire to the true/false value. This leaks privacy and
    /// should only be used in situations where it is okay to open the value
    /// to both parties. For example, in a statement value that will be
    /// opened anyways. Care should be taken that early opening does not leak
    /// privacy
    pub fn eq_zero_public(
        a: Variable,
        fabric: &Fabric,
        cs: &mut MpcPlonkCircuit,
    ) -> Result<BoolVar, CircuitError> {
        // Evaluate the value and open it to both parties, this does not require an
        // authenticated opening because a corrupted value will not be able to
        // satisfy the constraints
        let a_eval: AuthenticatedScalar = a.eval_multiprover(cs);
        let a_open: ScalarResult = AuthenticatedScalar::open(&a_eval);

        // Allocate a gate to check whether the underlying value is zero
        let mut res = fabric.new_batch_gate_op(vec![a_open.id()], 2 /* arity */, |mut args| {
            let val: Scalar = args.next().unwrap().into();
            let (is_zero, inv) = if val == Scalar::zero() {
                (Scalar::one(), Scalar::zero())
            } else {
                (Scalar::zero(), val.inverse())
            };

            vec![ResultValue::Scalar(is_zero), ResultValue::Scalar(inv)]
        });

        // Destructure the values and multiply them by 1 to get authenticated scalars
        let is_zero: ScalarResult = res.remove(0);
        let inverse: ScalarResult = res.remove(0);

        let one_authenticated = fabric.one_authenticated();
        let is_zero: AuthenticatedScalar = is_zero * &one_authenticated;
        let inverse: AuthenticatedScalar = inverse * &one_authenticated;

        // Proceed as in the single prover analog of the gadget
        let is_zero_var = is_zero.create_shared_witness(cs);
        let inv_var = inverse.create_shared_witness(cs);

        // Constrain `is_zero == 1 - val * inv`
        //
        // If the value is zero, then the right hand side will always be one, so the
        // circuit is well constrained
        //
        // If the value is non-zero (and inv is correctly assigned), then the right hand
        // side will be zero. The only check left is that inv is not set to
        // zero, allowing a non-zero `val` to satisfy the constraints with `is_zero = 1`
        // This is implicitly handled in the second constraint by ensuring that the
        // input times the output is zero, which for non-zero input is only true
        // if the output is zero
        let zero_var = cs.zero();
        let one_var = cs.one();
        let one = ScalarField::one();

        cs.mul_add_gate(&[a, inv_var, one_var, one_var, is_zero_var], &[-one, one])?;
        cs.mul_gate(is_zero_var, a, zero_var)?;

        // We do not need to enforce that the result is boolean, only 0 or 1 will
        // satisfy the previous two constraints
        Ok(BoolVar::new_unchecked(is_zero_var))
    }

    /// Computes whether the given inputs are equal to one another
    ///
    /// Note that this opens the values to both parties, see the method above
    pub fn eq_public<V: CircuitVarType>(
        a: &V,
        b: &V,
        fabric: &Fabric,
        cs: &mut MpcPlonkCircuit,
    ) -> Result<BoolVar, CircuitError> {
        let a_vars = a.to_vars();
        let b_vars = b.to_vars();

        Self::eq_vec_public(&a_vars, &b_vars, fabric, cs)
    }

    /// Computes whether the given vectors of inputs are equal
    ///
    /// Note that this opens the values to both parties, see the method above
    pub fn eq_vec_public<V: CircuitVarType>(
        a: &[V],
        b: &[V],
        fabric: &Fabric,
        cs: &mut MpcPlonkCircuit,
    ) -> Result<BoolVar, CircuitError> {
        assert_eq!(a.len(), b.len(), "eq_vec expects equal length vectors");
        let a_vals = a.iter().cloned().flat_map(|a_val| a_val.to_vars());
        let b_vals = b.iter().cloned().flat_map(|b_val| b_val.to_vars());

        let mut component_eq_vals = Vec::new();
        for (a_val, b_val) in a_vals.zip(b_vals) {
            let a_minus_b = cs.sub(a_val, b_val)?;
            let eq_val = Self::eq_zero_public(a_minus_b, fabric, cs)?;
            component_eq_vals.push(eq_val);
        }

        cs.logic_and_all(&component_eq_vals)
    }
}

/// A multiprover version of the greater than or equal to zero gadget
pub struct MultiproverGreaterThanEqZeroGadget<const D: usize>;
impl<const D: usize> MultiproverGreaterThanEqZeroGadget<D> {
    /// Constrains the input value to be greater than or equal to zero
    /// implicitly by bit-decomposing the value and re-composing it
    /// thereafter
    pub fn constrain_greater_than_eq_zero(
        x: Variable,
        fabric: &Fabric,
        cs: &mut MpcPlonkCircuit,
    ) -> Result<(), CircuitError> {
        MultiproverToBitsGadget::<D>::to_bits(x, fabric, cs).map(|_| ())
    }
}

/// A multiprover variant of the GreaterThanEqGadget
///
/// `D` is the bitlength of the input values
pub struct MultiproverGreaterThanEqGadget<const D: usize>;
impl<const D: usize> MultiproverGreaterThanEqGadget<D> {
    /// Constrain the relation a >= b
    pub fn constrain_greater_than_eq(
        a: Variable,
        b: Variable,
        fabric: &Fabric,
        cs: &mut MpcPlonkCircuit,
    ) -> Result<(), CircuitError> {
        let a_geq_b = cs.sub(a, b)?;
        MultiproverGreaterThanEqZeroGadget::<D>::constrain_greater_than_eq_zero(a_geq_b, fabric, cs)
    }
}

#[cfg(test)]
mod test {
    use ark_ff::One;
    use ark_mpc::{PARTY0, PARTY1};
    use circuit_types::{
        fixed_point::FixedPoint,
        order::{Order, OrderSide},
        traits::{CircuitBaseType, MpcBaseType, MultiproverCircuitBaseType},
        MpcPlonkCircuit, PlonkCircuit,
    };
    use constants::{Scalar, ScalarField};
    use mpc_relation::traits::Circuit;
    use num_bigint::RandBigInt;
    use rand::{seq::SliceRandom, thread_rng, Rng, RngCore};
    use test_helpers::mpc_network::execute_mock_mpc;

    use crate::{
        zk_gadgets::comparators::{
            EqGadget, GreaterThanEqGadget, GreaterThanEqZeroGadget, LessThanGadget,
            MultiproverEqGadget, MultiproverGreaterThanEqGadget,
            MultiproverGreaterThanEqZeroGadget,
        },
        SCALAR_MAX_BITS,
    };

    use super::EqZeroGadget;

    // -----------
    // | Helpers |
    // -----------

    /// Get a random order for testing
    fn random_order() -> Order {
        let mut rng = thread_rng();

        let bit_size = (SCALAR_MAX_BITS - 1) as u64;
        Order {
            quote_mint: rng.gen_biguint(bit_size),
            base_mint: rng.gen_biguint(bit_size),
            amount: rng.gen(),
            side: *[OrderSide::Buy, OrderSide::Sell].choose(&mut rng).unwrap(),
            worst_case_price: FixedPoint::from_f32_round_down(rng.gen()),
        }
    }

    // ---------
    // | Tests |
    // ---------

    /// Tests the `EqZeroGadget`
    #[test]
    fn test_eq_zero() {
        let mut rng = thread_rng();
        let a = Scalar::random(&mut rng);
        let zero = Scalar::zero();

        let mut cs = PlonkCircuit::new_turbo_plonk();
        let a_var = a.create_witness(&mut cs);
        let zero_var = zero.create_witness(&mut cs);

        let eq_zero1 = EqZeroGadget::eq_zero(&a_var, &mut cs).unwrap();
        let eq_zero2 = EqZeroGadget::eq_zero(&zero_var, &mut cs).unwrap();

        cs.enforce_false(eq_zero1).unwrap();
        cs.enforce_true(eq_zero2).unwrap();

        assert!(cs.check_circuit_satisfiability(&[]).is_ok());
    }

    /// Tests the `EqGadget`
    ///
    /// We use orders here but the type can be abstract
    #[test]
    fn test_eq_gadget() {
        let o1 = random_order();
        let o2 = random_order();

        let mut cs = PlonkCircuit::new_turbo_plonk();
        let o1_var = o1.create_witness(&mut cs);
        let o2_var = o2.create_witness(&mut cs);

        let eq1 = EqGadget::eq(&o1_var, &o2_var, &mut cs).unwrap(); // o1 == o2
        let eq2 = EqGadget::eq(&o1_var, &o1_var, &mut cs).unwrap(); // o1 == o1
        EqGadget::constrain_eq(&o1_var, &o1_var, &mut cs).unwrap();

        cs.enforce_false(eq1).unwrap();
        cs.enforce_true(eq2).unwrap();

        assert!(cs.check_circuit_satisfiability(&[]).is_ok());
    }

    /// Tests the `MultiproverEqGadget`
    #[tokio::test]
    async fn test_eq_gadget_multiprover() {
        let o1 = random_order();
        let o2 = random_order();

        let (res, _) = execute_mock_mpc(move |fabric| {
            let o1 = o1.clone();
            let o2 = o2.clone();

            async move {
                let mut cs = MpcPlonkCircuit::new(fabric.clone());
                let o1_var = o1.allocate(PARTY0, &fabric).create_shared_witness(&mut cs);
                let o2_var = o2.allocate(PARTY1, &fabric).create_shared_witness(&mut cs);

                // o1 == o2
                let eq1 =
                    MultiproverEqGadget::eq_public(&o1_var, &o2_var, &fabric, &mut cs).unwrap();
                // o1 == o1
                let eq2 =
                    MultiproverEqGadget::eq_public(&o1_var, &o1_var, &fabric, &mut cs).unwrap();

                cs.enforce_false(eq1).unwrap();
                cs.enforce_true(eq2).unwrap();

                cs.check_circuit_satisfiability(&[]).is_ok()
            }
        })
        .await;

        assert!(res);
    }

    #[test]
    #[rustfmt::skip]
    fn test_geq_gadget() {
        let mut rng = thread_rng();

        const BITS: usize = 64;
        let a = rng.next_u64();
        let b = rng.next_u64();

        // Order the two
        let (a, b) = if a > b { (a, b) } else { (b, a) };

        let mut cs = PlonkCircuit::new_turbo_plonk();
        let a_var = a.create_witness(&mut cs);
        let a_neg = cs.mul_constant(a_var, &-ScalarField::one()).unwrap();
        let b_var = b.create_witness(&mut cs);

        let geq_zero1 = GreaterThanEqZeroGadget::<BITS>::greater_than_eq_zero(a_var, &mut cs).unwrap(); // a > 0
        let geq_zero2 = GreaterThanEqZeroGadget::<BITS>::greater_than_eq_zero(a_neg, &mut cs).unwrap(); // -a > 0
        GreaterThanEqZeroGadget::<BITS>::constrain_greater_than_eq_zero(a_var, &mut cs).unwrap();

        let geq1 = GreaterThanEqGadget::<BITS>::greater_than_eq(a_var, b_var, &mut cs).unwrap(); // a >= b
        let geq2 = GreaterThanEqGadget::<BITS>::greater_than_eq(b_var, a_var, &mut cs).unwrap(); // b >= a 
        let geq3 = GreaterThanEqGadget::<BITS>::greater_than_eq(a_var, a_var, &mut cs).unwrap(); // a >= a
        GreaterThanEqGadget::<BITS>::constrain_greater_than_eq(a_var, b_var, &mut cs).unwrap();

        let lt1 = LessThanGadget::<BITS>::less_than(a_var, b_var, &mut cs).unwrap(); // a < b
        let lt2 = LessThanGadget::<BITS>::less_than(b_var, a_var, &mut cs).unwrap(); // b < a
        let lt3 = LessThanGadget::<BITS>::less_than(a_var, a_var, &mut cs).unwrap(); // a < a
        LessThanGadget::<BITS>::constrain_less_than(b_var, a_var, &mut cs).unwrap();

        cs.enforce_true(geq_zero1).unwrap();
        cs.enforce_false(geq_zero2).unwrap();
        cs.enforce_true(geq1).unwrap();
        cs.enforce_false(geq2).unwrap();
        cs.enforce_true(geq3).unwrap();
        cs.enforce_false(lt1).unwrap();
        cs.enforce_true(lt2).unwrap();
        cs.enforce_false(lt3).unwrap();

        assert!(cs.check_circuit_satisfiability(&[]).is_ok());
    }

    #[tokio::test]
    async fn test_geq_multiprover() {
        let mut rng = thread_rng();

        const BITS: usize = 64;
        let a = rng.next_u64();
        let b = rng.next_u64();

        // Order the two
        let (a, b) = if a > b { (a, b) } else { (b, a) };

        let (res, _) = execute_mock_mpc(move |fabric| async move {
            let shared_a = a.allocate(PARTY0, &fabric);
            let shared_b = b.allocate(PARTY1, &fabric);

            // a >= 0
            let mut cs = MpcPlonkCircuit::new(fabric.clone());
            let a_var = shared_a.create_shared_witness(&mut cs);

            MultiproverGreaterThanEqZeroGadget::<BITS>::constrain_greater_than_eq_zero(
                a_var, &fabric, &mut cs,
            )
            .unwrap();
            let mut res = cs.check_circuit_satisfiability(&[]).is_ok();

            // -a >= 0
            let mut cs = MpcPlonkCircuit::new(fabric.clone());
            let a_var = shared_a.create_shared_witness(&mut cs);
            let neg_a = cs.mul_constant(a_var, &-ScalarField::one()).unwrap();

            MultiproverGreaterThanEqZeroGadget::<BITS>::constrain_greater_than_eq_zero(
                neg_a, &fabric, &mut cs,
            )
            .unwrap();
            res &= cs.check_circuit_satisfiability(&[]).is_err();

            // a >= b
            let mut cs = MpcPlonkCircuit::new(fabric.clone());
            let a_var = shared_a.create_shared_witness(&mut cs);
            let b_var = shared_b.create_shared_witness(&mut cs);

            MultiproverGreaterThanEqGadget::<BITS>::constrain_greater_than_eq(
                a_var, b_var, &fabric, &mut cs,
            )
            .unwrap();
            res &= cs.check_circuit_satisfiability(&[]).is_ok();

            // b >= a
            let mut cs = MpcPlonkCircuit::new(fabric.clone());
            let a_var = shared_a.create_shared_witness(&mut cs);
            let b_var = shared_b.create_shared_witness(&mut cs);

            MultiproverGreaterThanEqGadget::<BITS>::constrain_greater_than_eq(
                b_var, a_var, &fabric, &mut cs,
            )
            .unwrap();
            res &= cs.check_circuit_satisfiability(&[]).is_err();

            // a >= a
            let mut cs = MpcPlonkCircuit::new(fabric.clone());
            let a_var = shared_a.create_shared_witness(&mut cs);

            MultiproverGreaterThanEqGadget::<BITS>::constrain_greater_than_eq(
                a_var, a_var, &fabric, &mut cs,
            )
            .unwrap();
            res &= cs.check_circuit_satisfiability(&[]).is_ok();

            res
        })
        .await;

        assert!(res);
    }
}
