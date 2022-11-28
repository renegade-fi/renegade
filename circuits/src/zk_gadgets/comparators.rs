//! Groups gadgets for binary comparison operators

use std::marker::PhantomData;

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use itertools::Itertools;
use mpc_bulletproof::{
    r1cs::{LinearCombination, Prover, R1CSProof, RandomizableConstraintSystem, Verifier},
    r1cs_mpc::{MpcLinearCombination, MpcRandomizableConstraintSystem},
    BulletproofGens,
};
use mpc_ristretto::{beaver::SharedValueSource, network::MpcNetwork};
use rand_core::OsRng;

use crate::{
    errors::{ProverError, VerifierError},
    mpc::SharedFabric,
    mpc_gadgets::bits::{scalar_to_bits_le, to_bits_le},
    SingleProverCircuit, POSITIVE_SCALAR_MAX_BITS,
};

/// A gadget that enforces a value of a given bitlength is positive
#[derive(Clone, Debug)]
pub struct GreaterThanEqZeroGadget<const D: usize> {}

impl<const D: usize> GreaterThanEqZeroGadget<D> {
    /// Constrain the value to be greater than zero
    pub fn constrain_greater_than_zero<L, CS>(cs: &mut CS, val: L)
    where
        CS: RandomizableConstraintSystem,
        L: Into<LinearCombination> + Clone,
    {
        assert!(
            D <= POSITIVE_SCALAR_MAX_BITS,
            "a positive value may only have {:?} bits",
            POSITIVE_SCALAR_MAX_BITS
        );

        // Bit decompose the input
        let bits = scalar_to_bits_le(&cs.eval(&val.clone().into()))[..D]
            .iter()
            .map(|bit| cs.allocate(Some(*bit)).unwrap())
            .collect_vec();

        // Constrain the bit decomposition to be correct
        // This implicitly constrains the value to be greater than zero, i.e. if it can be represented
        // without the highest bit set, then it is greater than zero. This assumes a two's complement
        // representation
        let mut res = LinearCombination::default();
        for bit in bits.into_iter().rev() {
            res = res * Scalar::from(2u64) + bit
        }

        cs.constrain(res - val.into())
    }
}

/// The witness for the statement that a hidden value is greater than zero
#[derive(Clone, Debug)]
pub struct GreaterThanEqZeroWitness {
    /// The value attested to that must be greater than zero
    val: Scalar,
}

impl<const D: usize> SingleProverCircuit for GreaterThanEqZeroGadget<D> {
    type Statement = ();
    type Witness = GreaterThanEqZeroWitness;
    type WitnessCommitment = CompressedRistretto;

    const BP_GENS_CAPACITY: usize = 256;

    fn prove(
        witness: Self::Witness,
        _: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
        // Commit to the witness
        let mut rng = OsRng {};
        let (witness_commit, witness_var) = prover.commit(witness.val, Scalar::random(&mut rng));

        // Apply the constraints
        Self::constrain_greater_than_zero(&mut prover, witness_var);

        // Prove the statement
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        let proof = prover.prove(&bp_gens).map_err(ProverError::R1CS)?;

        Ok((witness_commit, proof))
    }

    fn verify(
        witness_commitment: Self::WitnessCommitment,
        _: Self::Statement,
        proof: R1CSProof,
        mut verifier: Verifier,
    ) -> Result<(), VerifierError> {
        // Commit to the witness
        let witness_var = verifier.commit(witness_commitment);

        // Apply the constraints
        Self::constrain_greater_than_zero(&mut verifier, witness_var);

        // Verify the proof
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}

/// A multiprover version of the greater than or equal to zero gadget
pub struct MultiproverGreaterThanEqZeroGadget<
    'a,
    const D: usize,
    N: 'a + MpcNetwork + Send,
    S: 'a + SharedValueSource<Scalar>,
> {
    _phantom: &'a PhantomData<(N, S)>,
}

impl<'a, const D: usize, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>>
    MultiproverGreaterThanEqZeroGadget<'a, D, N, S>
{
    /// Constrains the input value to be greater than or equal to zero implicitly
    /// by bit-decomposing the value and re-composing it thereafter
    pub fn constrain_greater_than_zero<L, CS>(
        cs: &mut CS,
        val: L,
        fabric: SharedFabric<N, S>,
    ) -> Result<(), ProverError>
    where
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
        L: Into<MpcLinearCombination<N, S>> + Clone,
    {
        // Evaluate the assignment of the value in the underlying constraint system
        let value_assignment = cs
            .eval(&val.clone().into())
            .map_err(ProverError::Collaborative)?;
        let bits = to_bits_le::<D, N, S>(&value_assignment, fabric)
            .map_err(ProverError::Mpc)?
            .into_iter()
            .map(|bit| cs.allocate(Some(bit)).unwrap())
            .collect_vec();

        // Constrain the bit decomposition to be correct
        // This implicitly constrains the value to be greater than zero, i.e. if it can be represented
        // without the highest bit set, then it is greater than zero. This assumes a two's complement
        // representation
        let mut res = MpcLinearCombination::default();
        for bit in bits.into_iter().rev() {
            res = res * Scalar::from(2u64) + bit;
        }

        cs.constrain(res - val.into());
        Ok(())
    }
}

/// Enforces the constraint a >= b
///
/// `D` is the bitlength of the values being compared
pub struct GreaterThanEqGadget<const D: usize> {}

impl<const D: usize> GreaterThanEqGadget<D> {
    /// Constrains the values to satisfy a >= b
    pub fn constrain_greater_than_eq<L, CS>(cs: &mut CS, a: L, b: L)
    where
        CS: RandomizableConstraintSystem,
        L: Into<LinearCombination> + Clone,
    {
        GreaterThanEqZeroGadget::<D>::constrain_greater_than_zero(cs, a.into() - b.into());
    }
}

/// The witness for the statement a >= b; used for testing
///
/// Here, both `a` and `b` are private variables
#[allow(missing_docs)]
#[derive(Clone, Debug)]
pub struct GreaterThanEqWitness {
    pub a: Scalar,
    pub b: Scalar,
}

impl<const D: usize> SingleProverCircuit for GreaterThanEqGadget<D> {
    type Statement = ();
    type Witness = GreaterThanEqWitness;
    type WitnessCommitment = Vec<CompressedRistretto>;

    const BP_GENS_CAPACITY: usize = 64;

    fn prove(
        witness: Self::Witness,
        _: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
        // Commit to the witness
        let mut rng = OsRng {};
        let (a_comm, a_var) = prover.commit(witness.a, Scalar::random(&mut rng));
        let (b_comm, b_var) = prover.commit(witness.b, Scalar::random(&mut rng));

        // Apply the constraints
        Self::constrain_greater_than_eq(&mut prover, a_var, b_var);

        // Prove the statement
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        let proof = prover.prove(&bp_gens).map_err(ProverError::R1CS)?;

        Ok((vec![a_comm, b_comm], proof))
    }

    fn verify(
        witness_commitment: Self::WitnessCommitment,
        _: Self::Statement,
        proof: R1CSProof,
        mut verifier: Verifier,
    ) -> Result<(), VerifierError> {
        // Commit to the witness
        let a_var = verifier.commit(witness_commitment[0]);
        let b_var = verifier.commit(witness_commitment[1]);

        // Apply the constraints
        Self::constrain_greater_than_eq(&mut verifier, a_var, b_var);

        // Verify the proof
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}

/// A multiprover variant of the GreaterThanEqGadget
///
/// `D` is the bitlength of the input values
pub struct MultiproverGreaterThanEqGadget<
    'a,
    const D: usize,
    N: 'a + MpcNetwork + Send,
    S: 'a + SharedValueSource<Scalar>,
> {
    _phantom: &'a PhantomData<(N, S)>,
}

impl<'a, const D: usize, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>>
    MultiproverGreaterThanEqGadget<'a, D, N, S>
{
    /// Constrain the relation a >= b
    pub fn constrain_greater_than_eq<L, CS>(
        cs: &mut CS,
        a: L,
        b: L,
        fabric: SharedFabric<N, S>,
    ) -> Result<(), ProverError>
    where
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
        L: Into<MpcLinearCombination<N, S>> + Clone,
    {
        MultiproverGreaterThanEqZeroGadget::<'a, D, N, S>::constrain_greater_than_zero(
            cs,
            a.into() - b.into(),
            fabric,
        )
    }
}

#[cfg(test)]
mod comparators_test {
    use std::{cmp, ops::Neg};

    use curve25519_dalek::scalar::Scalar;
    use rand_core::{OsRng, RngCore};

    use crate::{errors::VerifierError, test_helpers::bulletproof_prove_and_verify};

    use super::{
        GreaterThanEqGadget, GreaterThanEqWitness, GreaterThanEqZeroGadget,
        GreaterThanEqZeroWitness,
    };

    /// Test the greater than zero constraint
    #[test]
    fn test_greater_than_zero() {
        let mut rng = OsRng {};

        // Test first with a positive value
        let value1 = Scalar::from(rng.next_u64());
        let witness = GreaterThanEqZeroWitness { val: value1 };

        bulletproof_prove_and_verify::<GreaterThanEqZeroGadget<64 /* bitlength */>>(witness, ())
            .unwrap();

        // Test with a negative value
        let value2 = value1.neg();
        let witness = GreaterThanEqZeroWitness { val: value2 };
        assert!(matches!(
            bulletproof_prove_and_verify::<GreaterThanEqZeroGadget<64 /* bitlength */>>(
                witness,
                ()
            ),
            Err(VerifierError::R1CS(_))
        ));
    }

    /// Test the greater than or equal to constraint
    #[test]
    fn test_greater_than_eq() {
        let mut rng = OsRng {};
        let a = rng.next_u64();
        let b = rng.next_u64();

        let max = Scalar::from(cmp::max(a, b));
        let min = Scalar::from(cmp::min(a, b));

        // Test first with a valid witness
        let witness = GreaterThanEqWitness { a: max, b: min };
        bulletproof_prove_and_verify::<GreaterThanEqGadget<64 /* bitlength */>>(witness, ())
            .unwrap();

        // Test with equal values
        let witness = GreaterThanEqWitness { a: max, b: max };
        bulletproof_prove_and_verify::<GreaterThanEqGadget<64 /* bitlength */>>(witness, ())
            .unwrap();

        // Test with an invalid witness
        let witness = GreaterThanEqWitness { a: min, b: max };
        assert!(matches!(
            bulletproof_prove_and_verify::<GreaterThanEqGadget<64 /* bitlength */>>(witness, ()),
            Err(VerifierError::R1CS(_))
        ));
    }
}
