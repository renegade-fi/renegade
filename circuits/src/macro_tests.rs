//! Defines tests for macros in the `circuit_macros` crate. We do this so that we may define the
//! bulk of the traits, data structures, etc outside of the `circuit-macros` crate; as a proc-macro
//! crate cannot export non proc-macro items

#[allow(clippy::missing_docs_in_private_items)]
#[cfg(test)]
mod test {
    use std::{cell::RefCell, rc::Rc};

    use circuit_macros::circuit_type;
    use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
    use integration_helpers::mpc_network::mocks::{MockMpcNet, PartyIDBeaverSource};
    use merlin::Transcript;
    use mpc_bulletproof::{
        r1cs::{Prover, Variable, Verifier},
        PedersenGens,
    };
    use mpc_ristretto::{
        authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource, network::MpcNetwork,
    };
    use rand_core::OsRng;

    use crate::{
        mpc::{MpcFabric, SharedFabric},
        traits::{
            Allocate, BaseType, CircuitBaseType, CircuitCommitmentType, CircuitVarType,
            CommitPublic, CommitVerifier, CommitWitness, MpcBaseType, MpcType, Open,
        },
    };

    #[circuit_type(singleprover_circuit, mpc)]
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
        let serialized = a.clone().to_scalars();
        let deserialized = TestType::from_scalars(&mut serialized.into_iter());

        assert_eq!(a, deserialized)
    }

    #[test]
    fn test_circuit_base_type_implementation() {
        let a = TestType { val: Scalar::one() };

        let mut rng = OsRng {};
        let pedersen_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pedersen_gens, &mut transcript);

        // Verify that we can commit to the type as a witness or public
        let (_, comm) = a.commit_witness(&mut rng, &mut prover).unwrap();
        a.commit_public(&mut prover).unwrap();

        // Verify that the derived commitment type may be committed to in a verifier
        let mut transcript = Transcript::new(b"test");
        let mut verifier = Verifier::new(&pedersen_gens, &mut transcript);

        comm.commit_verifier(&mut verifier).unwrap();
    }

    #[test]
    fn test_circuit_base_type_derived_types() {
        let callback = |_: TestTypeCommitment| {};
        let a = TestType { val: Scalar::one() };

        let mut rng = OsRng {};
        let pedersen_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pedersen_gens, &mut transcript);

        // Commit to the type and verify that the callback typechecks
        let (_, comm) = a.commit_witness(&mut rng, &mut prover).unwrap();
        callback(comm);
    }

    #[tokio::test]
    async fn test_mpc_derived_type() {
        let handle = tokio::task::spawn_blocking(|| {
            // Setup a dummy value to allocate then open
            let dummy = TestType {
                val: Scalar::from(2u8),
            };

            // Mock an MPC network
            let dummy_network = Rc::new(RefCell::new(MockMpcNet::new()));
            let dummy_network_data = vec![Scalar::one(); 100];
            dummy_network
                .borrow_mut()
                .add_mock_scalars(dummy_network_data);
            let dummy_beaver_source = Rc::new(RefCell::new(PartyIDBeaverSource::new(
                0, /* party_id */
            )));

            let dummy_fabric = MpcFabric::new_with_network(
                0, /* party_id */
                dummy_network,
                dummy_beaver_source,
            );
            let shared_fabric = SharedFabric::new(dummy_fabric);

            // Allocate the dummy value in the network
            let allocated = dummy
                .allocate(1 /* owning_party */, shared_fabric.clone())
                .unwrap();

            // Open the allocated value back to its original
            allocated.open(shared_fabric).unwrap();
        });

        handle.await.unwrap();
    }
}
