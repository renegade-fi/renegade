//! Groups ZK gadgets used as arithmetic primitives in more complicated computations

use std::marker::PhantomData;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use mpc_bulletproof::r1cs::{
    LinearCombination, Prover, R1CSProof, RandomizableConstraintSystem, Variable, Verifier,
};
use mpc_bulletproof::r1cs_mpc::{MpcLinearCombination, MpcRandomizableConstraintSystem};
use mpc_bulletproof::BulletproofGens;
use mpc_ristretto::{beaver::SharedValueSource, network::MpcNetwork};
use rand_core::OsRng;

use crate::mpc::SharedFabric;
use crate::SingleProverCircuit;

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
    x: Scalar,
}

/// The statement type for the ExpGadget circuit implementation
///
/// Both the exponent and the expected output are considered public inputs
/// to the proof.
#[derive(Copy, Clone, Debug)]
pub struct ExpGadgetStatement {
    /// Exponent
    alpha: u64,
    /// Expected result
    expected_out: Scalar,
}

impl SingleProverCircuit for ExpGadget {
    type Witness = ExpGadgetWitness;
    type Statement = ExpGadgetStatement;

    const BP_GENS_CAPACITY: usize = 64;

    fn prove(
        &self,
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<
        (
            Vec<curve25519_dalek::ristretto::CompressedRistretto>,
            mpc_bulletproof::r1cs::R1CSProof,
        ),
        mpc_bulletproof::r1cs_mpc::R1CSError,
    > {
        // Commit to the input and expected output
        let mut rng = OsRng {};
        let blinding_factor = Scalar::random(&mut rng);

        let (x_commit, x_var) = prover.commit(witness.x, blinding_factor);
        let (out_commit, out_var) = prover.commit_public(statement.expected_out);

        // Generate the constraints for the circuit
        Self::generate_constraints(&mut prover, x_var, out_var, statement.alpha);

        let bp_gens = BulletproofGens::new(
            Self::BP_GENS_CAPACITY, /* gens_capacity */
            1,                      /* party_capacity */
        );
        let proof = prover.prove(&bp_gens)?;

        // Only return the commitment to the witness, the verifier will separately commit to the statement input
        Ok((vec![x_commit, out_commit], proof))
    }

    fn verify(
        &self,
        witness_commitments: &[CompressedRistretto],
        statement: Self::Statement,
        proof: R1CSProof,
        mut verifier: Verifier,
    ) -> Result<(), mpc_bulletproof::r1cs_mpc::R1CSError> {
        // Commit to the result in the verifier
        let x_var = verifier.commit(witness_commitments[0]); // The input `x`
                                                             // let out_var = verifier.commit(witness_commitments[1]); // The output `y`
        let out_var = verifier.commit_public(statement.expected_out);

        // Generate the constraints for the circuit
        Self::generate_constraints(&mut verifier, x_var, out_var, statement.alpha);

        let bp_gens = BulletproofGens::new(
            Self::BP_GENS_CAPACITY, /* gens_capacity */
            1,                      /* party_capacity */
        );
        verifier.verify(&proof, &bp_gens)
    }
}

/// A multiprover implementation of the exp gadget
///
/// TODO: Implementation
pub struct MultiproverExpGadget<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    _phantom: PhantomData<(N, S)>,
}

#[allow(unused_variables)]
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> MultiproverExpGadget<N, S> {
    /// Apply the gadget to the input
    pub fn gadget<'a, CS, L>(
        cs: &mut CS,
        x: L,
        alpha: u64,
        fabric: SharedFabric<N, S>,
    ) -> MpcLinearCombination<N, S>
    where
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
        L: Into<MpcLinearCombination<N, S>>,
    {
        MpcLinearCombination::from_scalar(Scalar::zero(), fabric.0)
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
        bulletproof_prove_and_verify(
            ExpGadgetWitness { x: random_value },
            ExpGadgetStatement {
                alpha: alpha as u64,
                expected_out: expected_scalar,
            },
            ExpGadget {},
        )
        .unwrap();
    }
}
