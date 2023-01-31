//! Groups gadgets for binary comparison operators

use std::marker::PhantomData;

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use itertools::Itertools;
use mpc_bulletproof::{
    r1cs::{
        ConstraintSystem, LinearCombination, Prover, R1CSProof, RandomizableConstraintSystem,
        Variable, Verifier,
    },
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

/// A gadget that returns whether a value is equal to zero
///
/// Its output is Variable::One() if the input is equal to zero,
/// or Variable::Zero() if not
#[derive(Clone, Debug)]
pub struct EqZeroGadget {}
impl EqZeroGadget {
    /// Computes whether the given input is equal to zero
    ///
    /// Relies on the fact that modulo a prime field, all elements (except zero)
    /// have a valid multiplicative inverse
    pub fn eq_zero<L, CS>(val: L, cs: &mut CS) -> Variable
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        // Compute the inverse of the value outside the constraint
        let val_lc: LinearCombination = val.into();
        let val_eval = cs.eval(&val_lc);

        let (is_zero, inverse) = if val_eval == Scalar::zero() {
            (Scalar::one(), Scalar::zero())
        } else {
            (Scalar::zero(), val_eval.invert())
        };

        // Constrain the inverse to be computed correctly and such that
        //  is_zero == 1 - inv * val
        // If the input is zero, inv * val should be zero, and is_zero should be one
        // If the input is non-zero, inv * val should be one, and is_zero should be zero
        let is_zero_var = cs.allocate(Some(is_zero)).unwrap();
        let inv_var = cs.allocate(Some(inverse)).unwrap();
        let (_, _, val_times_inv) = cs.multiply(val_lc.clone(), inv_var.into());
        cs.constrain(is_zero_var - Scalar::one() + val_times_inv);

        // Constrain the input times the output to equal zero, this handles the edge case in the
        // above constraint in which the value is one, the prover assigns inv and is_zero such
        // that inv is neither zero nor one
        // I.e. the only way to satisfy this constraint when the value is non-zero is if is_zero == 0
        let (_, _, in_times_out) = cs.multiply(val_lc, is_zero_var.into());
        cs.constrain(in_times_out.into());

        is_zero_var
    }
}

impl SingleProverCircuit for EqZeroGadget {
    type Statement = bool;
    type Witness = Scalar;
    type WitnessCommitment = CompressedRistretto;

    const BP_GENS_CAPACITY: usize = 32;

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
        // Commit to the witness
        let mut rng = OsRng {};
        let (witness_comm, witness_var) = prover.commit(witness, Scalar::random(&mut rng));

        // Commit to the statement
        let expected_var = prover.commit_public(Scalar::from(statement as u8));

        // Test equality to zero and constrain this to be expected
        let eq_zero = EqZeroGadget::eq_zero(witness_var, &mut prover);
        prover.constrain(eq_zero - expected_var);

        // Prover the statement
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
        // Commit to the witness
        let witness_var = verifier.commit(witness_commitment);

        // Commit to the statement
        let expected_var = verifier.commit_public(Scalar::from(statement as u8));

        // Test equality to zero and constrain this to be expected
        let eq_zero = EqZeroGadget::eq_zero(witness_var, &mut verifier);
        verifier.constrain(eq_zero - expected_var);

        // Verify the proof
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}

/// Returns 1 if a == b otherwise 0
#[derive(Clone, Debug)]
pub struct EqGadget {}
impl EqGadget {
    /// Computes a == b
    pub fn eq<L, CS>(a: L, b: L, cs: &mut CS) -> Variable
    where
        L: Into<LinearCombination>,
        CS: RandomizableConstraintSystem,
    {
        EqZeroGadget::eq_zero(a.into() - b.into(), cs)
    }
}

/// Returns 1 if a_i = b_i for all i, otherwise 0
#[derive(Clone, Debug)]
pub struct EqVecGadget {}
impl EqVecGadget {
    /// Returns 1 if \vec{a} = \vec{b}, otherwise 0
    pub fn eq_vec<L, CS>(a: &[L], b: &[L], cs: &mut CS) -> Variable
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        assert_eq!(a.len(), b.len(), "eq_vec expects equal length vectors");

        // Compare each vector element
        let mut not_equal_values = Vec::with_capacity(a.len());
        for (a_val, b_val) in a.iter().zip(b.iter()) {
            not_equal_values.push(NotEqualGadget::not_equal(a_val.clone(), b_val.clone(), cs));
        }

        // Sum up all the a_i != b_i and return whether this value equals zero
        let mut not_equal_sum: LinearCombination = Variable::Zero().into();
        for ne_val in not_equal_values.iter() {
            not_equal_sum += ne_val.clone();
        }

        EqZeroGadget::eq_zero(not_equal_sum, cs)
    }
}

/// Returns a boolean representing a != b where 1 is true and 0 is false
#[derive(Debug)]
pub struct NotEqualGadget {}

impl NotEqualGadget {
    /// Computes a != b
    pub fn not_equal<L, CS>(a: L, b: L, cs: &mut CS) -> LinearCombination
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        let eq_zero = EqZeroGadget::eq_zero(a.into() - b.into(), cs);
        Variable::One() - eq_zero
    }
}

/// A gadget that enforces a value of a given bitlength is positive
#[derive(Clone, Debug)]
pub struct GreaterThanEqZeroGadget<const D: usize> {}
impl<const D: usize> GreaterThanEqZeroGadget<D> {
    /// Evaluate the condition x >= 0; returns 1 if true, otherwise 0
    pub fn greater_than_zero<L, CS>(x: L, cs: &mut CS) -> Variable
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        // If we can reconstruct the value without the highest bit, the value is non-negative
        let bit_reconstructed = Self::bit_decompose_reconstruct(x.clone(), cs);
        EqZeroGadget::eq_zero(bit_reconstructed - x.into(), cs)
    }

    /// Constrain the value to be greater than zero
    pub fn constrain_greater_than_zero<L, CS>(x: L, cs: &mut CS)
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        // If we can reconstruct the value without the highest bit, the value is non-negative
        let bit_reconstructed = Self::bit_decompose_reconstruct(x.clone(), cs);
        cs.constrain(bit_reconstructed - x.into())
    }

    /// A helper function to decompose a scalar into bits and then reconstruct it;
    /// returns the reconstructed result
    ///
    /// This is used by limiting the bit width of the decomposition -- if a value can
    /// be reconstructed without its highest bit (i.e. highest bit is zero) then it is
    /// non-negative
    fn bit_decompose_reconstruct<L, CS>(x: L, cs: &mut CS) -> LinearCombination
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        assert!(
            D <= POSITIVE_SCALAR_MAX_BITS,
            "a positive value may only have {:?} bits",
            POSITIVE_SCALAR_MAX_BITS
        );

        // Bit decompose the input
        let bits = scalar_to_bits_le(&cs.eval(&x.into()))[..D]
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

        res
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
        Self::constrain_greater_than_zero(witness_var, &mut prover);

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
        Self::constrain_greater_than_zero(witness_var, &mut verifier);

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
    /// Phantom
    _phantom: &'a PhantomData<(N, S)>,
}

impl<'a, const D: usize, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>>
    MultiproverGreaterThanEqZeroGadget<'a, D, N, S>
{
    /// Constrains the input value to be greater than or equal to zero implicitly
    /// by bit-decomposing the value and re-composing it thereafter
    pub fn constrain_greater_than_zero<L, CS>(
        x: L,
        fabric: SharedFabric<N, S>,
        cs: &mut CS,
    ) -> Result<(), ProverError>
    where
        L: Into<MpcLinearCombination<N, S>> + Clone,
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
    {
        let reconstructed_res = Self::bit_decompose_reconstruct(x.clone(), fabric, cs)?;
        cs.constrain(reconstructed_res - x.into());
        Ok(())
    }

    /// A helper function to compute the bit decomposition of an allocated scalar and
    /// then reconstruct from the bit decomposition.
    ///
    /// This is useful because we can bit decompose with all but the highest bit. If the
    /// reconstructed result is equal to the input; the highest bit is not set and the
    /// value is non-negative
    fn bit_decompose_reconstruct<L, CS>(
        x: L,
        fabric: SharedFabric<N, S>,
        cs: &mut CS,
    ) -> Result<MpcLinearCombination<N, S>, ProverError>
    where
        L: Into<MpcLinearCombination<N, S>> + Clone,
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
    {
        // Evaluate the assignment of the value in the underlying constraint system
        let value_assignment = cs.eval(&x.into()).map_err(ProverError::Collaborative)?;
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

        Ok(res)
    }
}

/// Enforces the constraint a >= b
///
/// `D` is the bitlength of the values being compared
pub struct GreaterThanEqGadget<const D: usize> {}
impl<const D: usize> GreaterThanEqGadget<D> {
    /// Evaluates the comparator a >= b; returns 1 if true, otherwise 0
    pub fn greater_than_eq<L, CS>(a: L, b: L, cs: &mut CS) -> Variable
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        GreaterThanEqZeroGadget::<D>::greater_than_zero(a.into() - b.into(), cs)
    }

    /// Constrains the values to satisfy a >= b
    pub fn constrain_greater_than_eq<L, CS>(a: L, b: L, cs: &mut CS)
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        GreaterThanEqZeroGadget::<D>::constrain_greater_than_zero(a.into() - b.into(), cs);
    }
}

/// The witness for the statement a >= b; used for testing
///
/// Here, both `a` and `b` are private variables
#[allow(missing_docs, clippy::missing_docs_in_private_items)]
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
        Self::constrain_greater_than_eq(a_var, b_var, &mut prover);

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
        Self::constrain_greater_than_eq(a_var, b_var, &mut verifier);

        // Verify the proof
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}

/// Gadget for a < b
///
/// D is the bitlength of the inputs
#[derive(Clone, Debug)]
pub struct LessThanGadget<const D: usize> {}
impl<const D: usize> LessThanGadget<D> {
    /// Compute the boolean a < b; returns 1 if true, otherwise 0
    pub fn less_than<L, CS>(a: L, b: L, cs: &mut CS) -> LinearCombination
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        let a_geq_b = GreaterThanEqGadget::<D>::greater_than_eq(a, b, cs);
        Variable::One() - a_geq_b
    }

    /// Constrain a to be less than b
    pub fn constrain_less_than<L, CS>(a: L, b: L, cs: &mut CS)
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        let lt_result = Self::less_than(a, b, cs);
        cs.constrain(Variable::One() - lt_result);
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
    /// Phantom
    _phantom: &'a PhantomData<(N, S)>,
}

impl<'a, const D: usize, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>>
    MultiproverGreaterThanEqGadget<'a, D, N, S>
{
    /// Constrain the relation a >= b
    pub fn constrain_greater_than_eq<L, CS>(
        a: L,
        b: L,
        fabric: SharedFabric<N, S>,
        cs: &mut CS,
    ) -> Result<(), ProverError>
    where
        L: Into<MpcLinearCombination<N, S>> + Clone,
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
    {
        MultiproverGreaterThanEqZeroGadget::<'a, D, N, S>::constrain_greater_than_zero(
            a.into() - b.into(),
            fabric,
            cs,
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
        EqZeroGadget, GreaterThanEqGadget, GreaterThanEqWitness, GreaterThanEqZeroGadget,
        GreaterThanEqZeroWitness,
    };

    /// Test the equal zero gadget
    #[test]
    fn test_eq_zero() {
        // First tests with a non-zero value
        let mut rng = OsRng {};
        let mut witness = Scalar::random(&mut rng);
        let mut statement = false; /* non-zero */

        let res = bulletproof_prove_and_verify::<EqZeroGadget>(witness, statement);
        assert!(res.is_ok());

        // Now test with the zero value
        witness = Scalar::zero();
        statement = true; /* zero */

        let res = bulletproof_prove_and_verify::<EqZeroGadget>(witness, statement);
        assert!(res.is_ok());
    }

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
