//! Groups ZK gadgets used as arithmetic primitives in more complicated computations

use std::marker::PhantomData;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use mpc_bulletproof::r1cs::{
    LinearCombination, Prover, R1CSProof, RandomizableConstraintSystem, Variable, Verifier,
};
use mpc_bulletproof::r1cs_mpc::{
    MpcConstraintSystem, MpcLinearCombination, MpcProver, MpcRandomizableConstraintSystem,
    SharedR1CSProof,
};
use mpc_bulletproof::BulletproofGens;
use mpc_ristretto::authenticated_ristretto::AuthenticatedCompressedRistretto;
use mpc_ristretto::authenticated_scalar::AuthenticatedScalar;
use mpc_ristretto::{beaver::SharedValueSource, network::MpcNetwork};
use rand_core::OsRng;

use crate::errors::{MpcError, ProverError, VerifierError};
use crate::mpc::SharedFabric;
use crate::{MultiProverCircuit, SingleProverCircuit};

/**
 * Single prover implementation
 */

/// The inputs to the exp gadget
/// A gadget to compute exponentiation: x^\alpha
pub struct ExpGadget {}

impl ExpGadget {
    /// Computes a linear combination representing the result of taking x^\alpha
    ///
    /// Provides a functional interface for composing this gadget into a larger
    /// circuit.
    pub fn gadget<L, CS>(cs: &mut CS, x: L, alpha: u64) -> LinearCombination
    where
        L: Into<LinearCombination>,
        CS: RandomizableConstraintSystem,
    {
        if alpha == 0 {
            LinearCombination::from(Scalar::one())
        } else if alpha == 1 {
            x.into()
        } else if alpha % 2 == 0 {
            let recursive_result = ExpGadget::gadget(cs, x, alpha / 2);
            let (_, _, out_var) = cs.multiply(recursive_result.clone(), recursive_result);
            out_var.into()
        } else {
            let x_lc = x.into();
            let recursive_result = ExpGadget::gadget(cs, x_lc.clone(), (alpha - 1) / 2);
            let (_, _, out_var1) = cs.multiply(recursive_result.clone(), recursive_result);
            let (_, _, out_var2) = cs.multiply(out_var1.into(), x_lc);
            out_var2.into()
        }
    }

    /// Generate the constraints for the ExpGadget statement
    fn generate_constraints<CS: RandomizableConstraintSystem>(
        cs: &mut CS,
        x_var: Variable,
        y_var: Variable,
        alpha: u64,
    ) {
        // Commit to the inputs and output
        let res = Self::gadget(cs, x_var, alpha);
        cs.constrain(res - y_var);
    }
}

/// The witness type to the ExpGadget Circuit implementation
///
/// This circuit represents a proof of knowledge of some base that when raised to the
/// statement's exponent yields the statement's result.
///
/// This statement is not particularly useful and is moreso useful for testing the
/// gadget itself
#[derive(Clone, Debug)]
pub struct ExpGadgetWitness {
    /// Exponentiation base
    pub x: Scalar,
}

/// The statement type for the ExpGadget circuit implementation
///
/// Both the exponent and the expected output are considered public inputs
/// to the proof.
#[derive(Copy, Clone, Debug)]
pub struct ExpGadgetStatement {
    /// Exponent
    pub alpha: u64,
    /// Expected result
    pub expected_out: Scalar,
}

impl SingleProverCircuit for ExpGadget {
    type Witness = ExpGadgetWitness;
    type Statement = ExpGadgetStatement;
    type WitnessCommitment = CompressedRistretto;

    const BP_GENS_CAPACITY: usize = 64;

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
        // Commit to the input and expected output
        let mut rng = OsRng {};
        let blinding_factor = Scalar::random(&mut rng);

        let (x_commit, x_var) = prover.commit(witness.x, blinding_factor);
        let (_, out_var) = prover.commit_public(statement.expected_out);

        // Generate the constraints for the circuit
        Self::generate_constraints(&mut prover, x_var, out_var, statement.alpha);

        let bp_gens = BulletproofGens::new(
            Self::BP_GENS_CAPACITY, /* gens_capacity */
            1,                      /* party_capacity */
        );
        let proof = prover.prove(&bp_gens).map_err(ProverError::R1CS)?;

        // Only return the commitment to the witness, the verifier will separately commit to the statement input
        Ok((x_commit, proof))
    }

    fn verify(
        witness_commitment: CompressedRistretto,
        statement: Self::Statement,
        proof: R1CSProof,
        mut verifier: Verifier,
    ) -> Result<(), VerifierError> {
        // Commit to the result in the verifier
        let x_var = verifier.commit(witness_commitment); // The input `x`
        let out_var = verifier.commit_public(statement.expected_out);

        // Generate the constraints for the circuit
        Self::generate_constraints(&mut verifier, x_var, out_var, statement.alpha);

        let bp_gens = BulletproofGens::new(
            Self::BP_GENS_CAPACITY, /* gens_capacity */
            1,                      /* party_capacity */
        );
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}

/// A multiprover implementation of the exp gadget
///
/// TODO: Implementation
pub struct MultiproverExpGadget<'a, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>> {
    /// Phantom
    _phantom: PhantomData<&'a (N, S)>,
}

impl<'a, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>>
    MultiproverExpGadget<'a, N, S>
{
    /// Apply the gadget to the input
    pub fn gadget<CS, L>(
        cs: &mut CS,
        x: L,
        alpha: u64,
        fabric: SharedFabric<N, S>,
    ) -> Result<MpcLinearCombination<N, S>, ProverError>
    where
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
        L: Into<MpcLinearCombination<N, S>>,
    {
        if alpha == 0 {
            Ok(MpcLinearCombination::from_scalar(Scalar::one(), fabric.0))
        } else if alpha == 1 {
            Ok(x.into())
        } else if alpha % 2 == 0 {
            let recursive_result = MultiproverExpGadget::gadget(cs, x, alpha / 2, fabric)?;
            let (_, _, out_var) = cs
                .multiply(&recursive_result, &recursive_result)
                .map_err(ProverError::Collaborative)?;
            Ok(out_var.into())
        } else {
            let x_lc = x.into();
            let recursive_result =
                MultiproverExpGadget::gadget(cs, x_lc.clone(), (alpha - 1) / 2, fabric)?;
            let (_, _, out_var1) = cs
                .multiply(&recursive_result, &recursive_result)
                .map_err(ProverError::Collaborative)?;
            let (_, _, out_var2) = cs
                .multiply(&out_var1.into(), &x_lc)
                .map_err(ProverError::Collaborative)?;
            Ok(out_var2.into())
        }
    }
}

/// The witness type for the ExpGadget in the multiprover setting
///
/// This type is essentially the same witness type as the witness for
/// the single prover setting, but using the authenticated, secret shared
/// field
#[derive(Clone, Debug)]
pub struct MultiproverExpWitness<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// Exponentiation base
    pub x: AuthenticatedScalar<N, S>,
}

impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> MultiProverCircuit<'a, N, S>
    for MultiproverExpGadget<'a, N, S>
{
    /// Witness is the secret shared version of the single-prover witness, and the
    /// statement is the same as the single-prover case
    type Witness = MultiproverExpWitness<N, S>;
    type WitnessCommitment = AuthenticatedCompressedRistretto<N, S>;
    type Statement = ExpGadgetStatement;

    const BP_GENS_CAPACITY: usize = 2048;

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: MpcProver<'a, '_, '_, N, S>,
        fabric: SharedFabric<N, S>,
    ) -> Result<
        (
            AuthenticatedCompressedRistretto<N, S>,
            SharedR1CSProof<N, S>,
        ),
        ProverError,
    > {
        // Commit to the input
        let mut rng = OsRng {};
        let (witness_commit, witness_var) = prover
            .commit_preshared(&witness.x, Scalar::random(&mut rng))
            .map_err(|err| ProverError::Mpc(MpcError::SharingError(err.to_string())))?;

        // Commit to the public expected hash output
        // TODO: update this with a correct commit_public impl
        let (_, output_var) = prover.commit_public(statement.expected_out);

        // Apply the constraints to the prover
        let res = Self::gadget(&mut prover, witness_var, statement.alpha, fabric)?;
        prover.constrain(res - output_var);

        // Prove the statement
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        let proof = prover.prove(&bp_gens).map_err(ProverError::Collaborative)?;

        Ok((witness_commit, proof))
    }

    fn verify(
        witness_commitments: CompressedRistretto,
        statement: Self::Statement,
        proof: R1CSProof,
        verifier: Verifier,
    ) -> Result<(), VerifierError> {
        ExpGadget::verify(witness_commitments, statement, proof, verifier)
    }
}

#[cfg(test)]
mod arithmetic_tests {
    use curve25519_dalek::scalar::Scalar;
    use integration_helpers::mpc_network::field::get_ristretto_group_modulus;
    use num_bigint::BigUint;
    use rand_core::{OsRng, RngCore};

    use crate::{bigint_to_scalar, scalar_to_biguint, test_helpers::bulletproof_prove_and_verify};

    use super::{ExpGadget, ExpGadgetStatement, ExpGadgetWitness};

    /// Tests the single prover exponentiation gadget
    #[test]
    fn test_single_prover_exp() {
        // Generate a random input
        let mut rng = OsRng {};
        let alpha = rng.next_u32(); // Compute x^\alpha
        let random_value = Scalar::random(&mut rng);

        let random_bigint = scalar_to_biguint(&random_value);
        let expected_res =
            random_bigint.modpow(&BigUint::from(alpha), &get_ristretto_group_modulus());
        let expected_scalar = bigint_to_scalar(&expected_res.into());

        // Create the circuit
        bulletproof_prove_and_verify::<ExpGadget>(
            ExpGadgetWitness { x: random_value },
            ExpGadgetStatement {
                alpha: alpha as u64,
                expected_out: expected_scalar,
            },
        )
        .unwrap();
    }

    /// Tests that a single prover exp does not verify for incorrect values
    #[test]
    fn test_single_prover_exp_failure() {
        // Gerneate a random input
        let mut rng = OsRng {};
        let alpha = rng.next_u32();
        let random_value = Scalar::random(&mut rng);
        let random_out = Scalar::random(&mut rng);

        let res = bulletproof_prove_and_verify::<ExpGadget>(
            ExpGadgetWitness { x: random_value },
            ExpGadgetStatement {
                alpha: alpha as u64,
                expected_out: random_out,
            },
        );

        assert!(res.is_err());
    }
}
