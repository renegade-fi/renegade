//! Groups gadgets that compare two values

use std::{marker::PhantomData, ops::Neg};

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use mpc_bulletproof::{
    r1cs::{
        ConstraintSystem, LinearCombination, Prover, R1CSProof, RandomizableConstraintSystem,
        Verifier,
    },
    r1cs_mpc::{MpcLinearCombination, MpcRandomizableConstraintSystem, R1CSError},
    BulletproofGens,
};
use mpc_ristretto::{beaver::SharedValueSource, network::MpcNetwork};
use rand_core::OsRng;

use crate::{
    errors::{ProverError, VerifierError},
    mpc::SharedFabric,
    SingleProverCircuit, SCALAR_MAX_BITS,
};

use super::{
    bits::{MultiproverToBitsGadget, ToBitsGadget},
    gates::{MultiproverOrGate, OrGate},
};

/// Computes a < 0
///
/// D is the bitlength of the input
pub struct LessThanZeroGadget<const D: usize> {}

impl<const D: usize> LessThanZeroGadget<D> {
    /// Computes a < 0
    pub fn less_than_zero<L, CS>(cs: &mut CS, a: L) -> Result<LinearCombination, R1CSError>
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        let bits = ToBitsGadget::<SCALAR_MAX_BITS>::to_bits(cs, a)?;

        // For the field Dalek operates over, either the 251st or the 252nd bit can be set for a negative
        // number, so take the OR of these bits
        Ok(OrGate::or(cs, bits[251].to_owned(), bits[252].to_owned()))
    }
}

/// Multiprover implementation of the less than zero gadget
///
/// Computes a < 0
///
/// D is the bitlength of the input
pub struct MultiproverLessThanZeroGadget<
    'a,
    const D: usize,
    N: 'a + MpcNetwork + Send,
    S: 'a + SharedValueSource<Scalar>,
> {
    _phantom: &'a PhantomData<(N, S)>,
}

impl<'a, const D: usize, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>>
    MultiproverLessThanZeroGadget<'a, D, N, S>
{
    /// Computes a < 0
    pub fn less_than_zero<L, CS>(
        cs: &mut CS,
        a: L,
        fabric: SharedFabric<N, S>,
    ) -> Result<MpcLinearCombination<N, S>, ProverError>
    where
        L: Into<MpcLinearCombination<N, S>> + Clone,
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
    {
        let bits = MultiproverToBitsGadget::<'_, SCALAR_MAX_BITS, _, _>::to_bits(cs, a, fabric)?;

        MultiproverOrGate::or(cs, bits[250].to_owned(), bits[251].to_owned())
    }
}

/// Computes a < b
pub struct LessThanGadget<const D: usize> {}

impl<const D: usize> LessThanGadget<D> {
    /// Computes the binary relation a < b
    pub fn less_than<L, CS>(cs: &mut CS, a: L, b: L) -> Result<LinearCombination, R1CSError>
    where
        L: Into<LinearCombination>,
        CS: RandomizableConstraintSystem,
    {
        LessThanZeroGadget::<D>::less_than_zero(cs, a.into() - b.into())
    }
}

/// The multiprover implementation of the less than gadget
///
/// Computes a < b
pub struct MultiproverLessThanGadget<
    'a,
    const D: usize,
    N: MpcNetwork + Send,
    S: SharedValueSource<Scalar>,
> {
    _phantom: &'a PhantomData<(N, S)>,
}

impl<'a, const D: usize, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>>
    MultiproverLessThanGadget<'a, D, N, S>
{
    /// Computes a < b
    pub fn less_than<L, CS>(
        cs: &mut CS,
        a: L,
        b: L,
        fabric: SharedFabric<N, S>,
    ) -> Result<MpcLinearCombination<N, S>, ProverError>
    where
        L: Into<MpcLinearCombination<N, S>>,
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
    {
        MultiproverLessThanZeroGadget::<'_, D, _, _>::less_than_zero(
            cs,
            a.into() - b.into(),
            fabric,
        )
    }
}

/// Computes min(a, b)
pub struct MinGadget<const D: usize> {}

impl<const D: usize> MinGadget<D> {
    /// Computes min(a, b)
    pub fn min<L, CS>(cs: &mut CS, a: L, b: L) -> Result<LinearCombination, R1CSError>
    where
        CS: RandomizableConstraintSystem,
        L: Into<LinearCombination> + Clone,
    {
        let a_less_than_b = LessThanGadget::<D>::less_than(cs, a.clone(), b.clone())?;

        let (_, _, a_term) = cs.multiply(a_less_than_b.clone(), a.into());
        let (_, _, b_term) = cs.multiply(a_less_than_b.neg() + Scalar::one(), b.into());

        Ok(a_term + b_term)
    }
}

/// The witness to the min gadget circuit, where expected ?= min(a, b)
pub struct MinGadgetWitness {
    /// The first element
    pub a: Scalar,
    /// The second element
    pub b: Scalar,
}

/// Proves knowledge of the minimum of two private elements, mostly used for testing
impl<const D: usize> SingleProverCircuit for MinGadget<D> {
    type Statement = Scalar; // The expected minimum of the two
    type Witness = MinGadgetWitness; // The two elements
    type WitnessCommitment = [CompressedRistretto; 2];

    const BP_GENS_CAPACITY: usize = 256;

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
        // Commit to the witness
        let mut rng = OsRng {};
        let (a_comm, a_var) = prover.commit(witness.a, Scalar::random(&mut rng));
        let (b_comm, b_var) = prover.commit(witness.b, Scalar::random(&mut rng));

        // Commit to the statement var
        let (_, expected_var) = prover.commit_public(statement);

        // Add the constraints
        let res = MinGadget::<D>::min(&mut prover, a_var, b_var).map_err(ProverError::R1CS)?;

        prover.constrain(res - expected_var);

        // Prove the statement
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        let proof = prover.prove(&bp_gens).map_err(ProverError::R1CS)?;

        Ok(([a_comm, b_comm], proof))
    }

    fn verify(
        witness_commitment: Self::WitnessCommitment,
        statement: Self::Statement,
        proof: R1CSProof,
        mut verifier: Verifier,
    ) -> Result<(), crate::errors::VerifierError> {
        // Commit to the witness
        let a_var = verifier.commit(witness_commitment[0]);
        let b_var = verifier.commit(witness_commitment[1]);

        // Commit to the statement var
        let expected_var = verifier.commit_public(statement);

        // Add the constraints
        let res = MinGadget::<D>::min(&mut verifier, a_var, b_var).map_err(VerifierError::R1CS)?;

        verifier.constrain(res - expected_var);

        // Prove the statement
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}

/// Multiprover implementation of the min gadget
///
/// Computes min(a, b)
pub struct MultiproverMinGadget<
    'a,
    const D: usize,
    N: 'a + MpcNetwork + Send,
    S: 'a + SharedValueSource<Scalar>,
> {
    _phantom: &'a PhantomData<(N, S)>,
}

impl<'a, const D: usize, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>>
    MultiproverMinGadget<'a, D, N, S>
{
    /// Computes min(a, b)
    pub fn min<L, CS>(
        cs: &mut CS,
        a: L,
        b: L,
        fabric: SharedFabric<N, S>,
    ) -> Result<MpcLinearCombination<N, S>, ProverError>
    where
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
        L: Into<MpcLinearCombination<N, S>> + Clone,
    {
        let a_less_than_b = MultiproverLessThanGadget::<'_, D, _, _>::less_than(
            cs,
            a.clone(),
            b.clone(),
            fabric.clone(),
        )?;

        let (_, _, a_term) = cs
            .multiply(&a_less_than_b, &a.into())
            .map_err(ProverError::Collaborative)?;
        let (_, _, b_term) = cs
            .multiply(
                &(a_less_than_b.neg() + MpcLinearCombination::from_scalar(Scalar::one(), fabric.0)),
                &b.into(),
            )
            .map_err(ProverError::Collaborative)?;

        Ok(a_term + b_term)
    }
}

#[cfg(test)]
mod comparators_tests {
    use std::cmp;

    use curve25519_dalek::scalar::Scalar;
    use rand_core::{OsRng, RngCore};

    use crate::test_helpers::bulletproof_prove_and_verify;

    use super::{MinGadget, MinGadgetWitness};

    /// Test the min gadget
    #[test]
    fn test_min() {
        let mut rng = OsRng {};
        let a = rng.next_u64();
        let b = rng.next_u64();

        let witness = MinGadgetWitness {
            a: Scalar::from(a),
            b: Scalar::from(b),
        };

        let statement = Scalar::from(cmp::min(a, b));
        let res = bulletproof_prove_and_verify::<MinGadget<64>>(witness, statement);

        assert!(res.is_ok())
    }
}
