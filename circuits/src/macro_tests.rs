//! Defines tests for macros in the `circuit_macros` crate. We do this so that we may define the
//! bulk of the traits, data structures, etc outside of the `circuit-macros` crate; as a proc-macro
//! crate cannot export non proc-macro items

#[allow(clippy::missing_docs_in_private_items)]
#[cfg(test)]
mod test {
    use circuit_macros::circuit_type;
    use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
    use merlin::Transcript;
    use mpc_bulletproof::{
        r1cs::{Prover, Variable, Verifier},
        PedersenGens,
    };
    use rand_core::OsRng;

    use crate::{
        BaseType, CircuitBaseType, CircuitCommitmentType, CircuitVarType, CommitPublic,
        CommitVerifier, CommitWitness,
    };

    #[circuit_type(singleprover_circuit)]
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
}
