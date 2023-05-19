//! Groups gadgets for conditional selection

use std::marker::PhantomData;

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use itertools::Itertools;
use mpc_bulletproof::{
    r1cs::{
        LinearCombination, Prover, R1CSError, R1CSProof, RandomizableConstraintSystem, Variable,
        Verifier,
    },
    r1cs_mpc::{MpcLinearCombination, MpcRandomizableConstraintSystem},
    BulletproofGens,
};
use mpc_ristretto::{beaver::SharedValueSource, network::MpcNetwork};
use rand_core::OsRng;

use crate::{
    errors::{ProverError, VerifierError},
    mpc::SharedFabric,
    CommitPublic, CommitWitness, SingleProverCircuit,
};

/// Implements the control flow gate if selector { a } else { b }
pub struct CondSelectGadget {}

impl CondSelectGadget {
    /// Computes the control flow statement if selector { a } else { b }
    pub fn select<L, CS>(a: L, b: L, selector: L, cs: &mut CS) -> LinearCombination
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        // Computes selector * a + (1 - selector) * b
        let (_, _, mul1_out) = cs.multiply(a.into(), selector.clone().into());
        let (_, _, mul2_out) = cs.multiply(b.into(), Variable::One() - selector);

        mul1_out + mul2_out
    }
}

/// The witness for the testing statement in which a, b, and selector are private
#[derive(Clone, Debug)]
pub struct CondSelectWitness {
    /// The first option in the selection
    a: Scalar,
    /// The second option in the selection
    b: Scalar,
    /// The selector; decides between the two options
    selector: Scalar,
}

impl CommitWitness for CondSelectWitness {
    type CommitType = Vec<CompressedRistretto>;
    type VarType = (Variable, Variable, Variable);
    type ErrorType = ();

    fn commit_witness<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (a_comm, a_var) = prover.commit(self.a, Scalar::random(rng));
        let (b_comm, b_var) = prover.commit(self.b, Scalar::random(rng));
        let (sel_comm, sel_var) = prover.commit(self.selector, Scalar::random(rng));

        Ok(((a_var, b_var, sel_var), vec![a_comm, b_comm, sel_comm]))
    }
}

/// The statement of the expected result from a CondSelectGadget
#[derive(Clone, Debug)]
pub struct CondSelectStatement {
    /// The expected selection from the gadget
    expected: Scalar,
}

impl CommitPublic for CondSelectStatement {
    type VarType = Variable;
    type ErrorType = ();

    fn commit_public<CS: RandomizableConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Result<Self::VarType, Self::ErrorType> {
        Ok(cs.commit_public(self.expected))
    }
}

impl SingleProverCircuit for CondSelectGadget {
    type Statement = CondSelectStatement;
    type Witness = CondSelectWitness;
    type WitnessCommitment = Vec<CompressedRistretto>;

    const BP_GENS_CAPACITY: usize = 8;

    fn apply_constraints<CS: RandomizableConstraintSystem>(
        witness_var: <Self::Witness as CommitWitness>::VarType,
        statement_var: <Self::Statement as CommitPublic>::VarType,
        cs: &mut CS,
    ) -> Result<(), R1CSError> {
        // Apply the constraints over the allocated witness & statement
        let res = Self::select(witness_var.0, witness_var.1, witness_var.2, cs);
        cs.constrain(res - statement_var);
        Ok(())
    }

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
        // Commit to the witness
        let mut rng = OsRng {};
        let (witness_var, witness_comm) = witness.commit_witness(&mut rng, &mut prover).unwrap();

        let statement_var = statement.commit_public(&mut prover).unwrap();

        Self::apply_constraints(witness_var, statement_var, &mut prover).unwrap();

        // Prove the statement
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        let proof = prover.prove(&bp_gens).map_err(ProverError::R1CS)?;

        Ok((witness_comm, proof))
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

        let statement_var = statement.commit_public(&mut verifier).unwrap();

        let witness_var = (a_var, b_var, sel_var);

        Self::apply_constraints(witness_var, statement_var, &mut verifier).unwrap();

        // Verify the proof
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}

/// A multiprover version of the conditional select gadget
pub struct MultiproverCondSelectGadget<
    'a,
    N: 'a + MpcNetwork + Send,
    S: 'a + SharedValueSource<Scalar>,
> {
    /// Phantom
    _phantom: &'a PhantomData<(N, S)>,
}

impl<'a, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>>
    MultiproverCondSelectGadget<'a, N, S>
{
    /// Computes the control flow statement if selector { a } else { b }
    pub fn select<L, CS>(
        a: L,
        b: L,
        selector: L,
        fabric: SharedFabric<N, S>,
        cs: &mut CS,
    ) -> Result<MpcLinearCombination<N, S>, ProverError>
    where
        L: Into<MpcLinearCombination<N, S>> + Clone,
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
    {
        // Computes selector * a + (1 - selector) * b
        let (_, _, mul1_out) = cs
            .multiply(&a.into(), &selector.clone().into())
            .map_err(ProverError::Collaborative)?;
        let (_, _, mul2_out) = cs
            .multiply(
                &b.into(),
                &(MpcLinearCombination::from_scalar(Scalar::one(), fabric.0) - selector.into()),
            )
            .map_err(ProverError::Collaborative)?;

        Ok(mul1_out + mul2_out)
    }
}

/// Implements the control flow gate if selector { a } else { b }
/// where `a` and `b` are vectors of values
pub struct CondSelectVectorGadget {}

impl CondSelectVectorGadget {
    /// Implements the control flow statement if selector { a } else { b }
    pub fn select<L, CS>(a: &[L], b: &[L], selector: L, cs: &mut CS) -> Vec<LinearCombination>
    where
        CS: RandomizableConstraintSystem,
        L: Into<LinearCombination> + Clone,
    {
        assert_eq!(a.len(), b.len(), "a and b must be of equal length");
        let mut selected = Vec::with_capacity(a.len());
        for (a_val, b_val) in a.iter().zip(b.iter()) {
            selected.push(CondSelectGadget::select(
                a_val.clone(),
                b_val.clone(),
                selector.clone(),
                cs,
            ));
        }

        selected
    }
}

/// The witness for the vector cond select in which we constrain the conditional selection to be
/// equal to an expected value
#[derive(Clone, Debug)]
pub struct CondSelectVectorWitness {
    /// The first vector option in the selection
    a: Vec<Scalar>,
    /// The second vector option in the selection
    b: Vec<Scalar>,
    /// The selector bit; decides which vector to select
    selector: Scalar,
}

impl CommitWitness for CondSelectVectorWitness {
    type CommitType = Vec<CompressedRistretto>;
    type VarType = (Vec<Variable>, Vec<Variable>, Variable);
    type ErrorType = ();

    fn commit_witness<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (a_comms, a_vars): (Vec<_>, Vec<_>) = self
            .a
            .iter()
            .map(|&a_val| prover.commit(a_val, Scalar::random(rng)))
            .unzip();

        let (mut b_comms, b_vars): (Vec<_>, Vec<_>) = self
            .b
            .iter()
            .map(|&b_val| prover.commit(b_val, Scalar::random(rng)))
            .unzip();

        let (sel_comm, sel_var) = prover.commit(self.selector, Scalar::random(rng));

        let mut witness_comm = a_comms;
        witness_comm.append(&mut b_comms);
        witness_comm.push(sel_comm);

        Ok(((a_vars, b_vars, sel_var), witness_comm))
    }
}

/// The statement parameterization as described in the struct above
#[derive(Clone, Debug)]
pub struct CondSelectVectorStatement {
    /// The expected output from the selection
    expected: Vec<Scalar>,
}

impl CommitPublic for CondSelectVectorStatement {
    type VarType = Vec<Variable>;
    type ErrorType = ();

    fn commit_public<CS: RandomizableConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Result<Self::VarType, Self::ErrorType> {
        Ok(self
            .expected
            .iter()
            .map(|&expected_val| cs.commit_public(expected_val))
            .collect_vec())
    }
}

impl SingleProverCircuit for CondSelectVectorGadget {
    type Statement = CondSelectVectorStatement;
    type Witness = CondSelectVectorWitness;
    type WitnessCommitment = Vec<CompressedRistretto>;

    const BP_GENS_CAPACITY: usize = 64;

    fn apply_constraints<CS: RandomizableConstraintSystem>(
        witness_var: <Self::Witness as CommitWitness>::VarType,
        statement_var: <Self::Statement as CommitPublic>::VarType,
        cs: &mut CS,
    ) -> Result<(), R1CSError> {
        // Apply the constraints over the allocated witness & statement
        let res = Self::select(&witness_var.0, &witness_var.1, witness_var.2, cs);
        for (res_var, expected_var) in res.into_iter().zip(statement_var.into_iter()) {
            cs.constrain(res_var - expected_var);
        }
        Ok(())
    }

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
        // Commit to the witness
        let mut rng = OsRng {};
        let (witness_var, witness_comm) = witness.commit_witness(&mut rng, &mut prover).unwrap();

        // Commit to the statement
        let statement_var = statement.commit_public(&mut prover).unwrap();

        Self::apply_constraints(witness_var, statement_var, &mut prover).unwrap();

        // Prove the statement
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        let proof = prover.prove(&bp_gens).map_err(ProverError::R1CS)?;

        Ok((witness_comm, proof))
    }

    fn verify(
        witness_commitment: Self::WitnessCommitment,
        statement: Self::Statement,
        proof: R1CSProof,
        mut verifier: Verifier,
    ) -> Result<(), VerifierError> {
        // Destructure the commitments
        let n = statement.expected.len();
        let a_comms = witness_commitment[..n].to_vec();
        let b_comms = witness_commitment[n..2 * n].to_vec();
        let sel_comm = witness_commitment[2 * n];

        // Commit to the witness
        let a_vars = a_comms
            .into_iter()
            .map(|a_comm| verifier.commit(a_comm))
            .collect_vec();

        let b_vars = b_comms
            .into_iter()
            .map(|b_comm| verifier.commit(b_comm))
            .collect_vec();

        let sel_var = verifier.commit(sel_comm);

        // Commit to the statement
        let statement_var = statement.commit_public(&mut verifier).unwrap();

        let witness_var = (a_vars, b_vars, sel_var);

        Self::apply_constraints(witness_var, statement_var, &mut verifier).unwrap();

        // Verify the proof
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}

/// A multiprover variant of the CondSelectVectorGadget
///
/// TODO: Optimize this by batching
pub struct MultiproverCondSelectVectorGadget<
    'a,
    N: 'a + MpcNetwork + Send,
    S: 'a + SharedValueSource<Scalar>,
> {
    /// Phantom
    _phantom: &'a PhantomData<(N, S)>,
}

impl<'a, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>>
    MultiproverCondSelectVectorGadget<'a, N, S>
{
    /// Implements the control flow block if selector { a } else { b }
    /// where `a` and `b` are vectors
    pub fn select<L, CS>(
        cs: &mut CS,
        a: &[L],
        b: &[L],
        selector: L,
        fabric: SharedFabric<N, S>,
    ) -> Result<Vec<MpcLinearCombination<N, S>>, ProverError>
    where
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
        L: Into<MpcLinearCombination<N, S>> + Clone,
    {
        assert_eq!(a.len(), b.len(), "a and b must be of equal length");
        let mut selected = Vec::with_capacity(a.len());
        for (a_val, b_val) in a.iter().zip(b.iter()) {
            selected.push(MultiproverCondSelectGadget::select(
                a_val.clone(),
                b_val.clone(),
                selector.clone(),
                fabric.clone(),
                cs,
            )?)
        }

        Ok(selected)
    }
}

#[cfg(test)]
mod cond_select_test {
    use curve25519_dalek::scalar::Scalar;
    use itertools::Itertools;
    use rand_core::OsRng;

    use crate::{errors::VerifierError, test_helpers::bulletproof_prove_and_verify};

    use super::{
        CondSelectGadget, CondSelectStatement, CondSelectVectorGadget, CondSelectVectorStatement,
        CondSelectVectorWitness, CondSelectWitness,
    };

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
        bulletproof_prove_and_verify::<CondSelectGadget>(witness.clone(), statement).unwrap();

        // Invalid proof
        let statement = CondSelectStatement {
            expected: Scalar::random(&mut rng),
        };

        assert!(matches!(
            bulletproof_prove_and_verify::<CondSelectGadget>(witness, statement),
            Err(VerifierError::R1CS(_))
        ));
    }

    /// Test the cond select vector gadget
    #[test]
    fn test_cond_select_vector() {
        let n = 10;
        let mut rng = OsRng {};
        let a = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();
        let b = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();

        // Prove with selector = 1
        let mut witness = CondSelectVectorWitness {
            a: a.clone(),
            b: b.clone(),
            selector: Scalar::one(),
        };
        let statement = CondSelectVectorStatement { expected: a };
        bulletproof_prove_and_verify::<CondSelectVectorGadget>(witness.clone(), statement).unwrap();

        // Prove with selector = 0
        witness.selector = Scalar::zero();
        let statement = CondSelectVectorStatement { expected: b };
        bulletproof_prove_and_verify::<CondSelectVectorGadget>(witness.clone(), statement).unwrap();

        // Invalid proof
        let statement = CondSelectVectorStatement {
            expected: (0..n).map(|_| Scalar::random(&mut rng)).collect_vec(),
        };
        assert!(matches!(
            bulletproof_prove_and_verify::<CondSelectVectorGadget>(witness, statement),
            Err(VerifierError::R1CS(_))
        ));
    }
}
