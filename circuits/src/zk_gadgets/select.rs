//! Groups gadgets for conditional selection

use circuit_types::traits::CircuitVarType;
use constants::ScalarField;
use mpc_relation::{errors::CircuitError, traits::Circuit, BoolVar};

/// Implements the control flow gate if selector { a } else { b }
pub struct CondSelectGadget;
impl CondSelectGadget {
    /// Computes the control flow statement if selector { a } else { b }
    pub fn select<V, C>(a: &V, b: &V, selector: BoolVar, cs: &mut C) -> Result<V, CircuitError>
    where
        V: CircuitVarType,
        C: Circuit<ScalarField>,
    {
        let a_vars = a.to_vars();
        let b_vars = b.to_vars();
        assert_eq!(
            a_vars.len(),
            b_vars.len(),
            "a and b must be of equal length"
        );

        // Computes selector * a + (1 - selector) * b
        let mut res = Vec::with_capacity(a_vars.len());
        for (a_var, b_var) in a_vars.into_iter().zip(b_vars.into_iter()) {
            res.push(cs.mux(selector, a_var, b_var)?);
        }

        Ok(V::from_vars(&mut res.into_iter(), cs))
    }
}

/// Implements the control flow gate if selector { a } else { b }
/// where `a` and `b` are vectors of values
pub struct CondSelectVectorGadget {}
impl CondSelectVectorGadget {
    /// Implements the control flow statement if selector { a } else { b }
    pub fn select<V, C>(
        a: &[V],
        b: &[V],
        selector: BoolVar,
        cs: &mut C,
    ) -> Result<Vec<V>, CircuitError>
    where
        V: CircuitVarType,
        C: Circuit<ScalarField>,
    {
        assert_eq!(a.len(), b.len(), "a and b must be of equal length");

        let mut selected = Vec::with_capacity(a.len());
        for (a_val, b_val) in a.iter().zip(b.iter()) {
            selected.push(CondSelectGadget::select(a_val, b_val, selector, cs)?);
        }

        Ok(selected)
    }
}

#[cfg(test)]
mod cond_select_test {
    use ark_mpc::PARTY0;
    use circuit_types::{
        traits::{CircuitBaseType, MpcBaseType, MultiproverCircuitBaseType},
        MpcPlonkCircuit, PlonkCircuit,
    };
    use constants::Scalar;
    use mpc_relation::traits::Circuit;
    use rand::{rngs::OsRng, thread_rng};
    use test_helpers::mpc_network::execute_mock_mpc;

    use super::CondSelectGadget;

    /// Test the cond select gadget
    #[test]
    fn test_cond_select() {
        let mut rng = OsRng {};
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);

        // Build a constraint system
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let a_var = a.create_public_var(&mut cs);
        let b_var = b.create_public_var(&mut cs);

        // Selector = 1
        let selector = true.create_witness(&mut cs);
        let res = CondSelectGadget::select(&a_var, &b_var, selector, &mut cs).unwrap();

        cs.enforce_equal(res, a_var).unwrap();

        // Selector = 0
        let selector = false.create_witness(&mut cs);
        let res = CondSelectGadget::select(&a_var, &b_var, selector, &mut cs).unwrap();

        cs.enforce_equal(res, b_var).unwrap();

        assert!(cs
            .check_circuit_satisfiability(&[a.inner(), b.inner()])
            .is_ok());
    }

    /// Test the cond select gadget in a multiprover setting
    #[tokio::test]
    async fn test_cond_select_multiprover() {
        let mut rng = thread_rng();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);

        let (res, _) = execute_mock_mpc(move |fabric| async move {
            let a = a.allocate(PARTY0, &fabric);
            let b = b.allocate(PARTY0, &fabric);

            let mut cs = MpcPlonkCircuit::new(fabric.clone());
            let a_var = a.create_shared_public_var(&mut cs).unwrap();
            let b_var = b.create_shared_public_var(&mut cs).unwrap();

            // Selector = 1
            let sel = true.allocate(PARTY0, &fabric);
            let sel = sel.create_shared_witness(&mut cs).unwrap();

            let res = CondSelectGadget::select(&a_var, &b_var, sel, &mut cs).unwrap();
            cs.enforce_equal(res, a_var).unwrap();

            // Selector = 0
            let sel = false.allocate(PARTY0, &fabric);
            let sel = sel.create_shared_witness(&mut cs).unwrap();

            let res = CondSelectGadget::select(&a_var, &b_var, sel, &mut cs).unwrap();
            cs.enforce_equal(res, b_var).unwrap();

            cs.check_circuit_satisfiability(&[a, b])
        })
        .await;

        assert!(res.is_ok());
    }
}
