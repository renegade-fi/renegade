//! Groups gadgets for conditional selection

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use mpc_bulletproof::{
    r1cs::{
        ConstraintSystem, LinearCombination, Prover, R1CSProof, RandomizableConstraintSystem,
        Variable, Verifier,
    },
    BulletproofGens,
};
use rand_core::OsRng;

use crate::{
    errors::{ProverError, VerifierError},
    SingleProverCircuit,
};

/// Implements the control flow gate if selector { a } else { b }
pub struct CondSelectGadget {}

impl CondSelectGadget {
    fn select<L, CS>(cs: &mut CS, a: L, b: L, selector: L) -> LinearCombination
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        // Computes selector * a + (1 - selector) * b
        let (_, _, mul1_out) = cs.multiply(a.into(), selector.clone().into());
        let (_, _, mul2_out) = cs.multiply(b.into(), Variable::One() - selector.into());

        mul1_out + mul2_out
    }
}

/// The witness for the testing statement in which a, b, and selector are private
#[derive(Clone, Debug)]
pub struct CondSelectWitness {
    a: Scalar,
    b: Scalar,
    selector: Scalar,
}

/// The statement of the expected result from a CondSelectGadget
#[derive(Clone, Debug)]
pub struct CondSelectStatement {
    expected: Scalar,
}

impl SingleProverCircuit for CondSelectGadget {
    type Statement = CondSelectStatement;
    type Witness = CondSelectWitness;
    type WitnessCommitment = Vec<CompressedRistretto>;

    const BP_GENS_CAPACITY: usize = 8;

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
        // Commit to the witness
        let mut rng = OsRng {};
        let (a_comm, a_var) = prover.commit(witness.a, Scalar::random(&mut rng));
        let (b_comm, b_var) = prover.commit(witness.b, Scalar::random(&mut rng));
        let (sel_comm, sel_var) = prover.commit(witness.selector, Scalar::random(&mut rng));

        let (_, expected_var) = prover.commit_public(statement.expected);

        // Apply the constraints
        let res = Self::select(&mut prover, a_var, b_var, sel_var);
        prover.constrain(res - expected_var);

        // Prove the statement
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        let proof = prover.prove(&bp_gens).map_err(ProverError::R1CS)?;

        Ok((vec![a_comm, b_comm, sel_comm], proof))
    }

    fn verify(
        witness_commitment: Self::WitnessCommitment,
        statement: Self::Statement,
        proof: R1CSProof,
        mut verifier: Verifier,
    ) -> Result<(), VerifierError> {
        // Commit to the witness and statement
        let a_var = verifier.commit(witness_commitment[0]);
        let b_var = verifier.commit(witness_commitment[1]);
        let sel_var = verifier.commit(witness_commitment[2]);

        let expected_var = verifier.commit_public(statement.expected);

        // Apply the constraints
        let res = Self::select(&mut verifier, a_var, b_var, sel_var);
        verifier.constrain(res - expected_var);

        // Verify the proof
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}

#[cfg(test)]
mod cond_select_test {
    use curve25519_dalek::scalar::Scalar;
    use rand_core::OsRng;

    use crate::test_helpers::bulletproof_prove_and_verify;

    use super::{CondSelectGadget, CondSelectStatement, CondSelectWitness};

    /// Test the cond select gadget
    #[test]
    fn test_cond_select() {
        let mut rng = OsRng {};
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);

        // Prove with selector = 1
        let mut witness = CondSelectWitness {
            a,
            b,
            selector: Scalar::one(),
        };
        let statement = CondSelectStatement { expected: a };
        bulletproof_prove_and_verify::<CondSelectGadget>(witness.clone(), statement).unwrap();

        // Prove with selector = 0
        witness.selector = Scalar::zero();
        let statement = CondSelectStatement { expected: b };
        bulletproof_prove_and_verify::<CondSelectGadget>(witness, statement).unwrap();
    }
}
