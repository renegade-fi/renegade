//! Defines tests for macros in the `circuit_macros` crate. We do this so that
//! we may define the bulk of the traits, data structures, etc outside of the
//! `circuit-macros` crate; as a proc-macro crate cannot export non proc-macro
//! items

#[allow(clippy::missing_docs_in_private_items)]
#[cfg(test)]
mod test {
    use ark_mpc::PARTY0;
    use circuit_macros::circuit_type;
    use constants::{AuthenticatedScalar, Scalar};
    use mpc_plonk::multiprover::proof_system::MpcPlonkCircuit;
    use mpc_relation::{Circuit, PlonkCircuit, Variable};
    use std::ops::Add;
    use test_helpers::mpc_network::execute_mock_mpc;

    use crate::{
        traits::{
            BaseType, CircuitBaseType, CircuitVarType, MpcBaseType, MpcType,
            MultiproverCircuitBaseType, SecretShareBaseType, SecretShareType, SecretShareVarType,
        },
        Fabric,
    };

    #[circuit_type(singleprover_circuit, mpc, multiprover_circuit, secret_share)]
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestType {
        val: Scalar,
    }

    impl TestType {
        fn check_equal(&self, val: Scalar) -> bool {
            self.val.eq(&val)
        }
    }

    /// Test that the base type is appropriately preserved
    #[test]
    fn test_base_type_preserved() {
        // Test that the base type may still be constructed
        let a = TestType { val: Scalar::one() };
        assert!(a.check_equal(Scalar::one()))
    }

    /// Test that the `BaseType` trait was correctly implemented
    #[test]
    fn test_base_type_implementation() {
        let a = TestType {
            val: Scalar::from(2u8),
        };
        let serialized = a.to_scalars();
        let deserialized = TestType::from_scalars(&mut serialized.into_iter());

        assert_eq!(a, deserialized)
    }

    #[test]
    fn test_circuit_base_type_implementation() {
        let a = TestType { val: Scalar::one() };

        let mut circuit = PlonkCircuit::new_turbo_plonk();

        // Verify that we can commit to the type as a witness or public
        let _witness = a.create_witness(&mut circuit);
        let _public = a.create_public_var(&mut circuit);
    }

    #[test]
    fn test_circuit_base_type_derived_types() {
        let callback = |_: TestTypeVar| {};
        let a = TestType { val: Scalar::one() };

        let mut circuit = PlonkCircuit::new_turbo_plonk();

        // Commit to the type and verify that the callback typechecks
        let var = a.create_witness(&mut circuit);
        let var2 = TestTypeVar { val: 2 };
        callback(var);
        callback(var2);
    }

    #[tokio::test]
    async fn test_mpc_derived_type() {
        // Execute an MPC that allocates the value then opens it
        let (party0_res, party1_res) = execute_mock_mpc(|fabric| async move {
            let value = TestType {
                val: Scalar::from(2u8),
            };

            let allocated = value.allocate(PARTY0, &fabric);
            allocated.open().await
        })
        .await;

        // Verify that both parties saw the same value: `TestType { 2 }`
        let expected_value = TestType {
            val: Scalar::from(2u8),
        };
        assert_eq!(expected_value, party0_res.unwrap());
        assert_eq!(expected_value, party1_res.unwrap());
    }

    #[tokio::test]
    async fn test_multiprover_derived_types() {
        let (party0_res, party1_res) = execute_mock_mpc(|fabric| async move {
            // Setup a dummy value to allocate in the constraint system
            let value = TestType {
                val: Scalar::from(2u8),
            };

            let mut circuit = MpcPlonkCircuit::new(fabric.clone());

            // Allocate the dummy value in the constraint system
            let dummy_allocated = value.allocate(PARTY0, &fabric);
            let shared_var = dummy_allocated.create_shared_witness(&mut circuit).unwrap();

            // Evaluate the first variable in the var type
            let eval: AuthenticatedTestType = shared_var.eval_multiprover(&circuit);
            eval.open_and_authenticate().await
        })
        .await;

        let expected_value = TestType {
            val: Scalar::from(2u8),
        };

        assert_eq!(party0_res.unwrap(), expected_value);
        assert_eq!(party1_res.unwrap(), expected_value);
    }

    #[test]
    fn test_secret_share_types() {
        // Build two secret shares
        let share1 = TestTypeShare { val: Scalar::one() };
        let share2 = TestTypeShare { val: Scalar::one() };

        let recovered = share1.clone() + share2;
        assert_eq!(recovered.val, Scalar::from(2u8));

        // Blind a secret share
        let blinded = share1.blind(Scalar::one());
        assert_eq!(blinded.val, Scalar::from(2u8));

        // Unblind a secret share
        let unblinded = blinded.unblind(Scalar::one());
        assert_eq!(unblinded.val, Scalar::one());
    }

    #[test]
    fn test_secret_share_vars() {
        // Build a secret share and allocate it
        let share = TestTypeShare { val: Scalar::one() };

        // Build a mock constraint system
        let mut circuit = PlonkCircuit::new_turbo_plonk();

        // Allocate the secret share in the constraint system
        let _ = share.create_witness(&mut circuit);
    }

    #[test]
    fn test_secret_share_var_arithmetic() {
        // Build two secret shares, allocate them in the constraint system, then
        // evaluate their sum
        let share1 = TestTypeShare { val: Scalar::one() };
        let share2 = TestTypeShare { val: Scalar::one() };

        // Build a mock prover
        let mut circuit = PlonkCircuit::new_turbo_plonk();

        let var1 = share1.create_witness(&mut circuit);
        let var2 = share2.create_witness(&mut circuit);

        let sum: TestType = var1.add_shares(&var2, &mut circuit).eval(&circuit);
        assert_eq!(
            TestType {
                val: Scalar::from(2u8)
            },
            sum
        );

        // Test blind and unblind
        let blinded = var1.blind(circuit.one(), &mut circuit);
        assert_eq!(
            TestType {
                val: Scalar::from(2u8)
            },
            blinded.val.eval(&circuit)
        );

        let unblinded = blinded.unblind(circuit.one(), &mut circuit);
        assert_eq!(TestType { val: Scalar::one() }, unblinded.eval(&circuit));
    }
}
