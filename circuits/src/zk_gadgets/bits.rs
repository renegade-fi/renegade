//! Groups gadgets for going from scalar -> bits and from bits -> scalar
use std::marker::PhantomData;

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use itertools::Itertools;
use mpc_bulletproof::{
    r1cs::{
        ConstraintSystem, LinearCombination, Prover, R1CSProof, RandomizableConstraintSystem,
        Verifier,
    },
    r1cs_mpc::{
        MpcConstraintSystem, MpcLinearCombination, MpcProver, MpcRandomizableConstraintSystem,
        R1CSError, SharedR1CSProof,
    },
    BulletproofGens,
};
use mpc_ristretto::{
    authenticated_ristretto::AuthenticatedCompressedRistretto,
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource, network::MpcNetwork,
};
use num_bigint::BigInt;
use rand_core::OsRng;

use crate::{
    bigint_to_scalar,
    errors::{MpcError, ProverError, VerifierError},
    mpc::SharedFabric,
    mpc_gadgets::bits::{scalar_to_bits_le, to_bits_le},
    MultiProverCircuit, Open, SingleProverCircuit,
};

/**
 * Single prover implementation
 */

pub struct ToBitsGadget<const D: usize> {}

impl<const D: usize> ToBitsGadget<D> {
    /// Converts a value to its bitwise representation in a single-prover constraint system
    pub fn to_bits<L, CS>(cs: &mut CS, a: L) -> Result<Vec<LinearCombination>, R1CSError>
    where
        CS: RandomizableConstraintSystem,
        L: Into<LinearCombination> + Clone,
    {
        let a_scalar = cs.eval(&a.clone().into());
        let bits = &scalar_to_bits_le(&a_scalar)[..D];

        let mut reconstructed = LinearCombination::default();
        let mut res_bits = Vec::with_capacity(D);
        for (index, bit) in bits.iter().enumerate() {
            let bit_lc = cs.allocate(Some(*bit))?;
            res_bits.push(bit_lc.into());

            let shift_bit = bigint_to_scalar(&(BigInt::from(1u64) << index));
            reconstructed += shift_bit * bit_lc;
        }

        cs.constrain(reconstructed - a.into());
        Ok(res_bits)
    }
}

/// The statement proved here is trivial, we prove the bit-decomposition of a given witness
/// scalar. This is, of course, not useful in practice, but is used for testing.
#[derive(Clone, Debug)]
pub struct ToBitsStatement {
    /// The expected bits from the decomposition
    pub bits: Vec<Scalar>,
}

impl<const D: usize> SingleProverCircuit for ToBitsGadget<D> {
    type Statement = ToBitsStatement;
    type Witness = Scalar;
    type WitnessCommitment = CompressedRistretto;

    const BP_GENS_CAPACITY: usize = 256;

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
        // Commit to the witness
        let mut rng = OsRng {};
        let (witness_comm, witness_var) = prover.commit(witness, Scalar::random(&mut rng));

        // Commit to the statement
        let (_, statement_vars): (Vec<_>, Vec<_>) = statement
            .bits
            .iter()
            .map(|bit| prover.commit_public(*bit))
            .unzip();

        // Get the bits result and constrain the output
        let res_bits = Self::to_bits(&mut prover, witness_var).map_err(ProverError::R1CS)?;

        for (statement_bit, res_bit) in statement_vars.into_iter().zip(res_bits.into_iter()) {
            prover.constrain(statement_bit - res_bit)
        }

        // Prove the statemetnb
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
        let witness_var = verifier.commit(witness_commitment);
        let bit_vars = statement
            .bits
            .into_iter()
            .map(|bit| verifier.commit_public(bit))
            .collect_vec();

        // Apply the constraints using the single-prover gadget
        let computed_bits =
            ToBitsGadget::<D>::to_bits(&mut verifier, witness_var).map_err(VerifierError::R1CS)?;
        for (statement_bit, computed_bit) in bit_vars.into_iter().zip(computed_bits.into_iter()) {
            verifier.constrain(statement_bit - computed_bit);
        }

        // Verify the proof
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}

/// Takes a scalar and returns its bit representation, constrained to be correct
///
/// D is the bitlength of the input vector to bitify
pub struct MultiproverToBitsGadget<
    'a,
    const D: usize,
    N: MpcNetwork + Send,
    S: SharedValueSource<Scalar>,
> {
    _phantom: &'a PhantomData<(N, S)>,
}

impl<'a, const D: usize, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>>
    MultiproverToBitsGadget<'a, D, N, S>
{
    /// Converts a value into its bitwise representation
    pub fn to_bits<L, CS>(
        cs: &mut CS,
        a: L,
        fabric: SharedFabric<N, S>,
    ) -> Result<Vec<MpcLinearCombination<N, S>>, ProverError>
    where
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
        L: Into<MpcLinearCombination<N, S>> + Clone,
    {
        // Evaluate the linear combination so that we can use a raw MPC to get the bits
        let a_scalar = cs
            .eval(&a.clone().into())
            .map_err(ProverError::Collaborative)?;

        // Convert the scalar to bits in a raw MPC gadget
        let bits = to_bits_le::<D /* bits */, N, S>(&a_scalar, fabric).map_err(ProverError::Mpc)?;

        // Allocate the bits in the constraint system, and constrain their inner product with
        // 1, 2, 4, ..., 2^{D-1} to be equal to the input value
        let mut reconstructed = MpcLinearCombination::default();
        let mut res_bits = Vec::with_capacity(D);
        for (index, bit) in bits.into_iter().enumerate() {
            let bit_lc = cs.allocate(Some(bit)).map_err(ProverError::R1CS)?;
            res_bits.push(bit_lc.clone().into());

            let shift_bit = bigint_to_scalar(&(BigInt::from(1u64) << index));
            reconstructed += shift_bit * bit_lc;
        }

        cs.constrain(reconstructed - a.into());

        Ok(res_bits)
    }
}

impl<'a, const D: usize, N: MpcNetwork + Send, S: SharedValueSource<Scalar>>
    MultiProverCircuit<'a, N, S> for MultiproverToBitsGadget<'a, D, N, S>
{
    type Statement = ToBitsStatement;
    type Witness = AuthenticatedScalar<N, S>;
    type WitnessCommitment = AuthenticatedCompressedRistretto<N, S>;

    const BP_GENS_CAPACITY: usize = 512;

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: MpcProver<'a, '_, '_, N, S>,
        fabric: SharedFabric<N, S>,
    ) -> Result<(Self::WitnessCommitment, SharedR1CSProof<N, S>), ProverError> {
        // Commit to the witness
        let mut rng = OsRng {};
        let (witness_comm, witness_var) = prover
            .commit_preshared(&witness, Scalar::random(&mut rng))
            .map_err(|err| ProverError::Mpc(MpcError::SharingError(err.to_string())))?;

        let (_, bit_vars) = prover.batch_commit_public(&statement.bits);

        // Apply the constraints
        let bits = Self::to_bits(&mut prover, witness_var, fabric)?;
        for (statement_bit, computed_bit) in bit_vars.into_iter().zip(bits.into_iter()) {
            prover.constrain(statement_bit - computed_bit);
        }

        // Generate a proof
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        let proof = prover.prove(&bp_gens).map_err(ProverError::Collaborative)?;

        Ok((witness_comm, proof))
    }

    fn verify(
        witness_commitments: <Self::WitnessCommitment as Open>::OpenOutput,
        statement: Self::Statement,
        proof: R1CSProof,
        verifier: Verifier,
    ) -> Result<(), VerifierError> {
        ToBitsGadget::<D>::verify(witness_commitments, statement, proof, verifier)
    }
}

#[cfg(test)]
mod bits_test {
    use curve25519_dalek::scalar::Scalar;
    use rand_core::{OsRng, RngCore};

    use crate::{
        bigint_to_scalar_bits, scalar_to_bigint, test_helpers::bulletproof_prove_and_verify,
    };

    use super::{ToBitsGadget, ToBitsStatement};

    /// Test that the to_bits single-prover gadget functions correctly
    #[test]
    fn test_to_bits() {
        // Create a random input to bitify
        let mut rng = OsRng {};
        let random_value = rng.next_u64();

        let witness = Scalar::from(random_value);

        // Create the statement by bitifying the input
        let bits = bigint_to_scalar_bits::<64 /* bits */>(&scalar_to_bigint(&witness));
        let statement = ToBitsStatement { bits };

        assert!(
            bulletproof_prove_and_verify::<ToBitsGadget<64 /* bits */>>(witness, statement).is_ok()
        );
    }
}
