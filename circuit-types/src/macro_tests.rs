//! Defines tests for macros in the `circuit_macros` crate. We do this so that
//! we may define the bulk of the traits, data structures, etc outside of the
//! `circuit-macros` crate; as a proc-macro crate cannot export non proc-macro
//! items

#[allow(clippy::missing_docs_in_private_items)]
#[cfg(test)]
mod test {
    use circuit_macros::circuit_type;
    use merlin::HashChainTranscript as Transcript;
    use mpc_bulletproof::{
        r1cs::{ConstraintSystem, LinearCombination, Prover, Variable, Verifier},
        r1cs_mpc::MpcProver,
        PedersenGens,
    };
    use mpc_stark::{
        algebra::{
            authenticated_scalar::AuthenticatedScalarResult,
            authenticated_stark_point::AuthenticatedStarkPointOpenResult, scalar::Scalar,
            stark_curve::StarkPoint,
        },
        MpcFabric, PARTY0,
    };
    use rand::{rngs::OsRng, thread_rng, CryptoRng, RngCore};
    use std::ops::Add;
    use test_helpers::mpc_network::execute_mock_mpc;

    use crate::{
        traits::{
            BaseType, CircuitBaseType, CircuitCommitmentType, CircuitVarType,
            LinearCombinationLike, LinkableBaseType, LinkableType, MpcBaseType,
            MpcLinearCombinationLike, MpcType, MultiproverCircuitBaseType,
            MultiproverCircuitCommitmentType, MultiproverCircuitVariableType, SecretShareBaseType,
            SecretShareType, SecretShareVarType,
        },
        LinkableCommitment,
    };

    #[circuit_type(
        singleprover_circuit,
        mpc,
        multiprover_circuit,
        linkable,
        multiprover_linkable,
        secret_share
    )]
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestType {
        val: Scalar,
    }

    impl TestType {
        fn check_equal(&self, val: Scalar) -> bool {
            self.val.eq(&val)
        }
    }

    #[test]
    fn test_base_type_preserved() {
        // Test that the base type may still be constructed
        let a = TestType { val: Scalar::one() };
        assert!(a.check_equal(Scalar::one()))
    }

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

        let mut rng = thread_rng();
        let pedersen_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pedersen_gens, &mut transcript);

        // Verify that we can commit to the type as a witness or public
        let (_, comm) = a.commit_witness(&mut rng, &mut prover);
        a.commit_public(&mut prover);

        // Verify that the derived commitment type may be committed to in a verifier
        let mut transcript = Transcript::new(b"test");
        let mut verifier = Verifier::new(&pedersen_gens, &mut transcript);

        comm.commit_verifier(&mut verifier);
    }

    #[test]
    fn test_circuit_base_type_derived_types() {
        let callback = |_: TestTypeCommitment| {};
        let a = TestType { val: Scalar::one() };

        let mut rng = thread_rng();
        let pedersen_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pedersen_gens, &mut transcript);

        // Commit to the type and verify that the callback typechecks
        let (_, comm) = a.commit_witness(&mut rng, &mut prover);
        callback(comm);
    }

    #[tokio::test]
    async fn test_mpc_derived_type() {
        // Execute an MPC that allocates the value then opens it
        let (party0_res, party1_res) = execute_mock_mpc(|fabric| async move {
            // Create the value inside the callback so that the callback can implement
            // `FnMut`, i.e. be called twice without taking ownership of `value`
            // or instead requiring static lifetime bounds
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
        // Execute an MPC in which the value is allocated in the constraint system
        // then opened to ensure the correct value
        let (party0_res, party1_res) = execute_mock_mpc(|fabric| async move {
            // Setup a dummy value to allocate in the constraint system
            let value = TestType {
                val: Scalar::from(2u8),
            };

            // Mock a shared prover
            let (comm, eval) = {
                let mut rng = OsRng {};
                let pc_gens = PedersenGens::default();
                let transcript = Transcript::new(b"test");
                let mut prover = MpcProver::new_with_fabric(fabric.clone(), transcript, pc_gens);

                // Allocate the dummy value in the constraint system
                let dummy_allocated = value.allocate(PARTY0, &fabric);
                let (shared_var, shared_comm) = dummy_allocated
                    .commit_shared(&mut rng, &mut prover)
                    .unwrap();

                // Evaluate the first variable in the var type
                let vars = shared_var.to_mpc_vars();
                let eval = prover.eval_lc(&vars[0].clone().into());
                (shared_comm, eval)
            }; // Explicitly drop `prover` here, it is not `Send` and cannot be held across an
               // `await` call

            let eval_open = eval.open_and_authenticate().await;
            let comm_open = comm.open_and_authenticate().await;

            (eval_open, comm_open)
        })
        .await;

        let (party0_eval, party0_comm) = party0_res;
        let (party1_eval, party1_comm) = party1_res;
        let expected_value = TestType {
            val: Scalar::from(2u8),
        };

        assert_eq!(party0_comm.unwrap(), party1_comm.unwrap());
        assert_eq!(party0_eval.unwrap(), expected_value.val);
        assert_eq!(party1_eval.unwrap(), expected_value.val);
    }

    #[test]
    fn test_linkable_commitments() {
        // Allocate a linkable type twice in the constraint system, verify that
        // its commitment stays the same
        let linkable_type = LinkableTestType {
            val: LinkableCommitment::from(Scalar::one()),
        };

        let pc_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        let mut rng = thread_rng();
        let (_, comm1) = linkable_type.commit_witness(&mut rng, &mut prover);
        let (_, comm2) = linkable_type.commit_witness(&mut rng, &mut prover);

        assert_eq!(comm1.val, comm2.val);
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
        let pc_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        // Allocate the secret share in the constraint system
        let mut rng = thread_rng();
        let _ = share.commit_witness(&mut rng, &mut prover);
    }

    #[test]
    fn test_secret_share_linkable_commitments() {
        // Build a secret share, commit to it twice, and verify the commitments are
        // equal
        let share = LinkableTestTypeShare {
            val: Scalar::one().into(),
        };

        // Build a mock constraint system
        let pc_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        let mut rng = thread_rng();
        let (_, comm1) = share.commit_witness(&mut rng, &mut prover);
        let (_, comm2) = share.commit_witness(&mut rng, &mut prover);

        assert_eq!(comm1.val, comm2.val);
    }

    #[test]
    fn test_secret_share_var_arithmetic() {
        // Build two secret shares, allocate them in the constraint system, then
        // evaluate their sum
        let share1 = TestTypeShare { val: Scalar::one() };
        let share2 = TestTypeShare { val: Scalar::one() };

        // Build a mock prover
        let pc_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        let mut rng = thread_rng();
        let (var1, _) = share1.commit_witness(&mut rng, &mut prover);
        let (var2, _) = share2.commit_witness(&mut rng, &mut prover);

        let sum = var1.clone() + var2;
        assert_eq!(Scalar::from(2u8), prover.eval(&sum.val));

        // Test blind and unblind
        let blinded = var1.blind(Variable::One());
        assert_eq!(Scalar::from(2u8), prover.eval(&blinded.val));

        let unblinded = blinded.unblind(Variable::One());
        assert_eq!(Scalar::one(), prover.eval(&unblinded.val));
    }
}
