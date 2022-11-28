//! Groups gadgets for binary comparison operators

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use itertools::Itertools;
use mpc_bulletproof::{
    r1cs::{LinearCombination, Prover, R1CSProof, RandomizableConstraintSystem, Verifier},
    BulletproofGens,
};
use rand_core::OsRng;

use crate::{
    errors::{ProverError, VerifierError},
    mpc_gadgets::bits::scalar_to_bits_le,
    SingleProverCircuit, POSITIVE_SCALAR_MAX_BITS,
};

/// A gadget that enforces a value of a given bitlength is positive
#[derive(Clone, Debug)]
pub struct GreaterThanZeroGadget<const D: usize> {}

impl<const D: usize> GreaterThanZeroGadget<D> {
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
pub struct GreaterThanZeroWitness {
    /// The value attested to that must be greater than zero
    val: Scalar,
}

impl<const D: usize> SingleProverCircuit for GreaterThanZeroGadget<D> {
    type Statement = ();
    type Witness = GreaterThanZeroWitness;
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

#[cfg(test)]
mod comparators_test {
    use std::ops::Neg;

    use curve25519_dalek::scalar::Scalar;
    use rand_core::{OsRng, RngCore};

    use crate::{errors::VerifierError, test_helpers::bulletproof_prove_and_verify};

    use super::{GreaterThanZeroGadget, GreaterThanZeroWitness};

    /// Test the greater than zero constraint
    #[test]
    fn test_greater_than_zero() {
        let mut rng = OsRng {};

        // Test first with a positive value
        let value1 = Scalar::from(rng.next_u64());
        let witness = GreaterThanZeroWitness { val: value1 };

        bulletproof_prove_and_verify::<GreaterThanZeroGadget<64 /* bitlength */>>(witness, ())
            .unwrap();

        // Test with a negative value
        let value2 = value1.neg();
        let witness = GreaterThanZeroWitness { val: value2 };
        assert!(if let Err(VerifierError::R1CS(_)) =
            bulletproof_prove_and_verify::<GreaterThanZeroGadget<64 /* bitlength */>>(witness, ())
        {
            true
        } else {
            false
        });
    }
}
