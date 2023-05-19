//! Groups ZK gadgets used as arithmetic primitives in more complicated computations

use std::marker::PhantomData;

use ark_ff::Zero;
use circuit_macros::circuit_trace;
use crypto::fields::{biguint_to_scalar, scalar_to_biguint};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use mpc_bulletproof::r1cs::{
    ConstraintSystem, LinearCombination, Prover, R1CSProof, RandomizableConstraintSystem, Variable,
    Verifier,
};
use mpc_bulletproof::r1cs_mpc::{
    MpcConstraintSystem, MpcLinearCombination, MpcProver, MpcRandomizableConstraintSystem,
    MpcVariable, R1CSError, SharedR1CSProof,
};
use mpc_bulletproof::BulletproofGens;
use mpc_ristretto::authenticated_ristretto::AuthenticatedCompressedRistretto;
use mpc_ristretto::authenticated_scalar::AuthenticatedScalar;
use mpc_ristretto::{beaver::SharedValueSource, network::MpcNetwork};
use num_bigint::BigUint;
use num_integer::Integer;
use rand_core::OsRng;

use crate::errors::{MpcError, ProverError, VerifierError};
use crate::mpc::SharedFabric;
use crate::{
    CommitPublic, CommitSharedProver, CommitWitness, MultiProverCircuit, SingleProverCircuit,
};

use super::bits::ToBitsGadget;
use super::comparators::{EqZeroGadget, LessThanGadget};
use super::select::CondSelectGadget;

// -------------------------
// | Single Prover Gadgets |
// -------------------------

/// A div-rem gadget which for inputs `a`, `b` returns
/// values `q`, `r` such that a = bq + r and r < b
///
/// The generic constant `D` represents the bitlength of the input `b`
#[derive(Clone, Debug)]
pub struct DivRemGadget<const D: usize> {}
impl<const D: usize> DivRemGadget<D> {
    /// Return (q, r) such that a = bq + r and r < b
    pub fn div_rem<L, CS>(a: L, b: L, cs: &mut CS) -> (Variable, Variable)
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        let a_lc: LinearCombination = a.into();
        let b_lc: LinearCombination = b.into();

        // Evaluate to bigint
        let a_bigint = scalar_to_biguint(&cs.eval(&a_lc));
        let b_bigint = scalar_to_biguint(&cs.eval(&b_lc));

        // Compute the divrem outside of the circuit
        // Verifier evals all wires to zero -- it only knows commitments
        // Handle this case explicitly
        let (q, r) = if b_bigint == BigUint::zero() {
            (BigUint::zero(), b_bigint)
        } else {
            a_bigint.div_rem(&b_bigint)
        };

        let q_var = cs.allocate(Some(biguint_to_scalar(&q))).unwrap();
        let r_var = cs.allocate(Some(biguint_to_scalar(&r))).unwrap();

        // Constrain a == bq + r
        let (_, _, bq) = cs.multiply(b_lc.clone(), q_var.into());
        cs.constrain(a_lc - bq - r_var);

        // Constraint r < b
        LessThanGadget::<D>::constrain_less_than(r_var.into(), b_lc, cs);
        (q_var, r_var)
    }
}

/// The inputs to the exp gadget
/// A gadget to compute exponentiation: x^\alpha
pub struct ExpGadget {}
impl ExpGadget {
    /// Computes a linear combination representing the result of taking x^\alpha
    ///
    /// Provides a functional interface for composing this gadget into a larger
    /// circuit.
    #[circuit_trace(latency)]
    pub fn exp<L, CS>(x: L, alpha: u64, cs: &mut CS) -> LinearCombination
    where
        L: Into<LinearCombination>,
        CS: RandomizableConstraintSystem,
    {
        if alpha == 0 {
            LinearCombination::from(Scalar::one())
        } else if alpha == 1 {
            x.into()
        } else if alpha % 2 == 0 {
            let recursive_result = ExpGadget::exp(x, alpha / 2, cs);
            let (_, _, out_var) = cs.multiply(recursive_result.clone(), recursive_result);
            out_var.into()
        } else {
            let x_lc = x.into();
            let recursive_result = ExpGadget::exp(x_lc.clone(), (alpha - 1) / 2, cs);
            let (_, _, out_var1) = cs.multiply(recursive_result.clone(), recursive_result);
            let (_, _, out_var2) = cs.multiply(out_var1.into(), x_lc);
            out_var2.into()
        }
    }

    /// Generate the constraints for the ExpGadget statement
    #[circuit_trace(latency)]
    fn generate_exp_constraints<CS: RandomizableConstraintSystem>(
        x_var: Variable,
        y_var: Variable,
        alpha: u64,
        cs: &mut CS,
    ) {
        // Commit to the inputs and output
        let res = Self::exp(x_var, alpha, cs);
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

impl CommitWitness for ExpGadgetWitness {
    type CommitType = CompressedRistretto;
    type VarType = Variable;
    type ErrorType = ();

    fn commit_witness<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (witness_comm, witness_var) = prover.commit(self.x, Scalar::random(rng));
        Ok((witness_var, witness_comm))
    }
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

impl CommitPublic for ExpGadgetStatement {
    type VarType = (Variable, u64);
    type ErrorType = ();

    fn commit_public<CS: RandomizableConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Result<Self::VarType, Self::ErrorType> {
        Ok((cs.commit_public(self.expected_out), self.alpha))
    }
}

impl SingleProverCircuit for ExpGadget {
    type Witness = ExpGadgetWitness;
    type Statement = ExpGadgetStatement;
    type WitnessCommitment = CompressedRistretto;

    const BP_GENS_CAPACITY: usize = 64;

    fn apply_constraints<CS: RandomizableConstraintSystem>(
        witness_var: <Self::Witness as CommitWitness>::VarType,
        statement_var: <Self::Statement as CommitPublic>::VarType,
        cs: &mut CS,
    ) -> Result<(), R1CSError> {
        // Apply the constraints over the allocated witness & statement
        Self::generate_exp_constraints(witness_var, statement_var.0, statement_var.1, cs);
        Ok(())
    }

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
        // Commit to the input and expected output
        let mut rng = OsRng {};

        let (witness_var, witness_commit) = witness.commit_witness(&mut rng, &mut prover).unwrap();
        let statement_var = statement.commit_public(&mut prover).unwrap();

        Self::apply_constraints(witness_var, statement_var, &mut prover).unwrap();

        let bp_gens = BulletproofGens::new(
            Self::BP_GENS_CAPACITY, /* gens_capacity */
            1,                      /* party_capacity */
        );
        let proof = prover.prove(&bp_gens).map_err(ProverError::R1CS)?;

        // Only return the commitment to the witness, the verifier will separately commit to the statement input
        Ok((witness_commit, proof))
    }

    fn verify(
        witness_commitment: CompressedRistretto,
        statement: Self::Statement,
        proof: R1CSProof,
        mut verifier: Verifier,
    ) -> Result<(), VerifierError> {
        // Commit to the result in the verifier
        let x_var = verifier.commit(witness_commitment); // The input `x`
        let statement_var = statement.commit_public(&mut verifier).unwrap();

        Self::apply_constraints(x_var, statement_var, &mut verifier).unwrap();

        let bp_gens = BulletproofGens::new(
            Self::BP_GENS_CAPACITY, /* gens_capacity */
            1,                      /* party_capacity */
        );
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}

/// An exponentiation gadget on a private exponent; compute x^\alpha
#[derive(Clone, Debug)]
pub struct PrivateExpGadget<const ALPHA_BITS: usize> {}

impl<const ALPHA_BITS: usize> PrivateExpGadget<ALPHA_BITS> {
    /// Compute x^\alpha where `x` is public and alpha is private
    pub fn exp_private_fixed_base<L, CS>(
        x: Scalar,
        alpha: L,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError>
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        // Bit decompose the exponent, this removes the need to check `is_odd` at every
        // iteration
        let alpha_bits = ToBitsGadget::<ALPHA_BITS>::to_bits(alpha, cs)?;
        Self::exp_private_fixed_base_impl::<L, CS>(x, &alpha_bits, cs)
    }

    /// Compute x^\alpha where both x and alpha are private values
    pub fn exp_private<L, CS>(x: L, alpha: L, cs: &mut CS) -> Result<LinearCombination, R1CSError>
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        // Bit decompose the exponent, this removes the need to check `is_odd` at every
        // iteration
        let alpha_bits = ToBitsGadget::<ALPHA_BITS>::to_bits(alpha, cs)?;

        let x_lc: LinearCombination = x.into();
        Self::exp_private_impl(x_lc, &alpha_bits, cs)
    }

    /// An implementation helper for fixed base exponentiation that assumes a bit decomposition of
    /// the exponent is passed in
    fn exp_private_fixed_base_impl<L, CS>(
        x: Scalar,
        alpha_bits: &[Variable],
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError>
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        if alpha_bits.is_empty() {
            return Ok(LinearCombination::from(Scalar::one()));
        }

        // Check whether all bits are zero
        let alpha_zero = Self::all_bits_zero(alpha_bits, cs);
        let is_odd = alpha_bits[0];

        // Recursive call
        let recursive_result = Self::exp_private_fixed_base_impl::<L, CS>(x, &alpha_bits[1..], cs)?;
        let (_, _, recursive_doubled) = cs.multiply(recursive_result.clone(), recursive_result);

        // If the value is odd multiply by an extra copy of `x`
        let recursive_plus_one = x * recursive_doubled;

        // Mux between the two results depending on whether the current exponent is odd or even
        let odd_bit_selection = CondSelectGadget::select(
            recursive_plus_one,
            recursive_doubled.into(),
            is_odd.into(),
            cs,
        );

        // Mask the value of the output if alpha is already zero
        let zero_mask = CondSelectGadget::select(
            Variable::One().into(),
            odd_bit_selection,
            alpha_zero.into(),
            cs,
        );

        Ok(zero_mask)
    }

    /// An implementation helper that assumes a bit decomposition of the exponent
    fn exp_private_impl<L, CS>(
        x: L,
        alpha_bits: &[Variable],
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError>
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        if alpha_bits.is_empty() {
            return Ok(LinearCombination::from(Scalar::one()));
        }

        let x_lc: LinearCombination = x.into();

        // Check whether all bits are zero
        let alpha_zero = Self::all_bits_zero(alpha_bits, cs);
        let is_odd = alpha_bits[0];

        // Recursive call
        let recursive_result = Self::exp_private_impl(x_lc.clone(), &alpha_bits[1..], cs)?;
        let (_, _, recursive_doubled) = cs.multiply(recursive_result.clone(), recursive_result);

        // If the value is odd multiply by an extra copy of `x`
        let (_, _, recursive_plus_one) = cs.multiply(x_lc, recursive_doubled.into());

        // Mux between the two results depending on whether the current exponent is odd or even
        let odd_bit_selection =
            CondSelectGadget::select(recursive_plus_one, recursive_doubled, is_odd, cs);

        // Mask the value of the output if alpha is already zero
        let zero_mask = CondSelectGadget::select(
            Variable::One().into(),
            odd_bit_selection,
            alpha_zero.into(),
            cs,
        );

        Ok(zero_mask)
    }

    /// Returns whether all the given bits are zero, it is assumed that these values
    /// are constrained to be binary elsewhere in the circuit
    fn all_bits_zero<L, CS>(bits: &[L], cs: &mut CS) -> Variable
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        // Add all the bits
        let mut bit_sum: LinearCombination = Variable::Zero().into();
        for bit in bits
            .iter()
            .map(|bit| Into::<LinearCombination>::into(bit.clone()))
        {
            bit_sum += bit;
        }

        EqZeroGadget::eq_zero(bit_sum, cs)
    }
}

/// The witness type for the [`PrivateExpGadget`] circuit implementation
///
/// Both the base and the exponent are private inputs
pub struct PrivateExpGadgetWitness {
    /// Base
    x: Scalar,
    /// Exponent
    alpha: Scalar,
}

impl CommitWitness for PrivateExpGadgetWitness {
    type CommitType = (CompressedRistretto, CompressedRistretto);
    type VarType = (Variable, Variable);
    type ErrorType = ();

    fn commit_witness<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (x_comm, x_var) = prover.commit(self.x, Scalar::random(rng));
        let (alpha_comm, alpha_var) = prover.commit(self.alpha, Scalar::random(rng));
        Ok(((x_var, alpha_var), (x_comm, alpha_comm)))
    }
}

impl<const ALPHA_SIZE: usize> SingleProverCircuit for PrivateExpGadget<ALPHA_SIZE> {
    /// Expected output
    type Statement = Scalar;
    /// (x, \alpha)
    type Witness = PrivateExpGadgetWitness;
    type WitnessCommitment = (CompressedRistretto, CompressedRistretto);

    const BP_GENS_CAPACITY: usize = 4096;

    fn apply_constraints<CS: RandomizableConstraintSystem>(
        witness_var: <Self::Witness as CommitWitness>::VarType,
        statement_var: <Self::Statement as CommitPublic>::VarType,
        cs: &mut CS,
    ) -> Result<(), R1CSError> {
        // Apply the constraints over the allocated witness & statement
        let res = Self::exp_private(witness_var.0, witness_var.1, cs)?;
        cs.constrain(res - statement_var);
        Ok(())
    }

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
        // Commit to `x` and `\alpha`
        let mut rng = OsRng {};
        let (witness_var, witness_comm) = witness.commit_witness(&mut rng, &mut prover).unwrap();

        // Commit to the expected output
        let expected_out = prover.commit_public(statement);

        Self::apply_constraints(witness_var, expected_out, &mut prover)
            .map_err(ProverError::R1CS)?;

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
        // Commit to `x` and `\alpha`
        let x_var = verifier.commit(witness_commitment.0);
        let alpha_var = verifier.commit(witness_commitment.1);

        // Commit to the expected output
        let expected_out = verifier.commit_public(statement);

        Self::apply_constraints((x_var, alpha_var), expected_out, &mut verifier)
            .map_err(VerifierError::R1CS)?;

        // Verify the proof
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}

// -----------------------
// | Multiprover Gadgets |
// -----------------------

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
    pub fn exp<L, CS>(
        x: L,
        alpha: u64,
        fabric: SharedFabric<N, S>,
        cs: &mut CS,
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
            let recursive_result = MultiproverExpGadget::exp(x, alpha / 2, fabric, cs)?;
            let (_, _, out_var) = cs
                .multiply(&recursive_result, &recursive_result)
                .map_err(ProverError::Collaborative)?;
            Ok(out_var.into())
        } else {
            let x_lc = x.into();
            let recursive_result =
                MultiproverExpGadget::exp(x_lc.clone(), (alpha - 1) / 2, fabric, cs)?;
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

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> CommitSharedProver<N, S>
    for MultiproverExpWitness<N, S>
{
    type CommitType = AuthenticatedCompressedRistretto<N, S>;
    type SharedVarType = MpcVariable<N, S>;
    type ErrorType = mpc_ristretto::error::MpcError;

    fn commit<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        _owning_party: u64,
        rng: &mut R,
        prover: &mut MpcProver<N, S>,
    ) -> Result<(Self::SharedVarType, Self::CommitType), Self::ErrorType> {
        let (witness_comm, witness_var) = prover.commit_preshared(&self.x, Scalar::random(rng))?;
        Ok((witness_var, witness_comm))
    }
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

    fn apply_constraints_multi_prover(
        witness_var: <Self::Witness as CommitSharedProver<N, S>>::SharedVarType,
        statement: Self::Statement,
        prover: &mut MpcProver<'a, '_, '_, N, S>,
        fabric: SharedFabric<N, S>,
    ) -> Result<(), ProverError> {
        // Commit to the public expected hash output
        // TODO: update this with a correct commit_public impl
        let (_, output_var) = prover.commit_public(statement.expected_out);

        // Apply the constraints to the prover
        let res = Self::exp(witness_var, statement.alpha, fabric, prover)?;
        prover.constrain(res - output_var);

        Ok(())
    }

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
        let (witness_var, witness_commit) = witness
            .commit(u64::MAX /* unused */, &mut rng, &mut prover)
            .map_err(|err| ProverError::Mpc(MpcError::SharingError(err.to_string())))?;

        Self::apply_constraints_multi_prover(witness_var, statement, &mut prover, fabric)?;

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
    use crypto::fields::{bigint_to_scalar, biguint_to_scalar, scalar_to_biguint};
    use curve25519_dalek::scalar::Scalar;
    use integration_helpers::mpc_network::field::get_ristretto_group_modulus;
    use merlin::Transcript;
    use mpc_bulletproof::{
        r1cs::{ConstraintSystem, Prover, Variable},
        PedersenGens,
    };
    use num_bigint::BigUint;
    use num_integer::Integer;
    use rand_core::{OsRng, RngCore};

    use crate::test_helpers::bulletproof_prove_and_verify;

    use super::{
        DivRemGadget, ExpGadget, ExpGadgetStatement, ExpGadgetWitness, PrivateExpGadget,
        PrivateExpGadgetWitness,
    };

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
        // Generate a random input
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

    /// Tests the single prover exponent gadget on a private exponent
    #[test]
    fn test_private_exp_gadget() {
        let mut rng = OsRng {};
        let alpha_bytes = 8;
        let mut random_bytes = vec![0u8; alpha_bytes];
        rng.fill_bytes(&mut random_bytes);

        let alpha = biguint_to_scalar(&BigUint::from_bytes_le(&random_bytes));
        let x = Scalar::random(&mut rng);

        // Compute the expected exponentiation result
        let x_bigint = scalar_to_biguint(&x);
        let alpha_bigint = scalar_to_biguint(&alpha);

        let expected = x_bigint.modpow(&alpha_bigint, &get_ristretto_group_modulus());

        let res = bulletproof_prove_and_verify::<PrivateExpGadget<64>>(
            PrivateExpGadgetWitness { x, alpha },
            biguint_to_scalar(&expected),
        );
        assert!(res.is_ok())
    }

    /// Tests the div_rem gadget
    #[test]
    fn test_div_rem() {
        // Sample random inputs
        let mut rng = OsRng {};
        let random_dividend = BigUint::from(rng.next_u32());
        let random_divisor = BigUint::from(rng.next_u32());

        let (expected_q, expected_r) = random_dividend.div_rem(&random_divisor);

        // Build a constraint system
        let mut prover_transcript = Transcript::new("test".as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        // Allocate the inputs in the constraint system
        let dividend_var = prover.commit_public(biguint_to_scalar(&random_dividend));
        let divisor_var = prover.commit_public(biguint_to_scalar(&random_divisor));

        let (q_res, r_res) =
            DivRemGadget::<32 /* bitlength */>::div_rem(dividend_var, divisor_var, &mut prover);
        prover.constrain(q_res - biguint_to_scalar(&expected_q) * Variable::One());
        prover.constrain(r_res - biguint_to_scalar(&expected_r) * Variable::One());

        assert!(prover.constraints_satisfied());
    }
}
