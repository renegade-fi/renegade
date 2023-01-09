//! Groups type definitions and arithmetic operators for bigints (up to U256)
//! allocated in a constraint system

use crypto::fields::{biguint_to_scalar, scalar_to_biguint};
use curve25519_dalek::scalar::Scalar;
use lazy_static::lazy_static;
use mpc_bulletproof::r1cs::{LinearCombination, RandomizableConstraintSystem, Variable};
use num_bigint::BigUint;

lazy_static! {
    static ref BIGINT_ZERO: BigUint = BigUint::from(0u8);
    static ref BIGINT_2_TO_4: BigUint = BigUint::from(1u8) << 4;
    static ref BIGINT_2_TO_126: BigUint = BigUint::from(1u8) << 126;
}

/// Return the quotient and remainder when dividing by the given modulus
///
/// Takes as input a constraint system so that we can implicitly constrain the
/// result to be valid without implementing full modulus computation in zero-knowledge
///
/// TODO: Do we need to constrain the result to have modulo < divisor?
fn div_rem_bigint<L, CS>(dividend: L, divisor: &BigUint, cs: &mut CS) -> (Variable, Variable)
where
    L: Into<LinearCombination>,
    CS: RandomizableConstraintSystem,
{
    // To ensure that the multiplications won't overflow
    assert!(*divisor <= BigUint::from(1u8) << 126);
    let dividend_lc: LinearCombination = dividend.into();

    // Evaluate the dividend into a bigint
    let dividend_scalar = cs.eval(&dividend_lc);
    let dividend_bigint = scalar_to_biguint(&dividend_scalar);

    // Compute the dividend and remainder
    let div_scalar = biguint_to_scalar(&(&dividend_bigint / divisor));
    let rem_scalar = biguint_to_scalar(&(dividend_bigint % divisor));

    // Allocate the values in the constraint system
    let div_var = cs.allocate(Some(div_scalar)).unwrap();
    let rem_var = cs.allocate(Some(rem_scalar)).unwrap();

    // Constrain the modulus to be computed correctly
    // i.e. quotient * divisor + remainder == dividend
    let divisor_scalar = biguint_to_scalar(divisor);
    cs.constrain(divisor_scalar * div_var + rem_var - dividend_lc);

    (div_var, rem_var)
}

/// Multiplies two allocated variables together and takes the product modulo
/// the given value
///
/// Returns the quotient and remainder from division
fn mul_mod_n<L, CS>(a: L, b: L, n: &BigUint, cs: &mut CS) -> (Variable, Variable)
where
    L: Into<LinearCombination>,
    CS: RandomizableConstraintSystem,
{
    let (_, _, mul_res) = cs.multiply(a.into(), b.into());
    div_rem_bigint(mul_res, n, cs)
}

/// Multiplies an allocated variable and a scalar and takes the product
/// modulo the given value
///
/// Returns the quotient and remainder from division
fn mul_scalar_mod_n<L, CS>(a: L, b: Scalar, n: &BigUint, cs: &mut CS) -> (Variable, Variable)
where
    L: Into<LinearCombination>,
    CS: RandomizableConstraintSystem,
{
    let mul_res = a.into() * b;
    div_rem_bigint(mul_res, n, cs)
}

/// Represents a bigint in the conslet mut rng = OsRtraint system
///
/// The maximum size is 256 bits
///
/// In the implementation, we use 126 bit increments because the Scalar
/// type is defined over a group of order slightly larger than 2^252, so
/// multiplying two 126-bit scalars won't overflow
#[derive(Clone, Copy, Debug)]
pub struct U256Var {
    /// The lowest 126 bits (bits [0, 125]) of the integrer
    pub low: Variable,
    /// The middle 126 bits (bits [126, 251]) of the integer
    pub middle: Variable,
    /// The top 4 bits (bits [252, 255]) of the integrer
    pub high: Variable,
}

impl U256Var {
    /// Construct a new U256
    pub fn new(low: Variable, middle: Variable, high: Variable) -> Self {
        Self { low, middle, high }
    }

    /// Construct a new U256 from a bigint, allocating the values in a constraint system
    pub fn from_biguint<CS: RandomizableConstraintSystem>(val: &BigUint, cs: &mut CS) -> Self {
        // Split into bitwise repr of high medium and low
        let (low_bits, middle_bits, high_bits) = Self::bigint_to_split_scalars(val);
        let low = cs.allocate(Some(low_bits)).unwrap();
        let middle = cs.allocate(Some(middle_bits)).unwrap();
        let high = cs.allocate(Some(high_bits)).unwrap();

        Self { low, middle, high }
    }

    /// Splits a bigint into high, medium, and low scalars
    fn bigint_to_split_scalars(val: &BigUint) -> (Scalar, Scalar, Scalar) {
        let two_to_126 = 1u128 << 126;
        let two_to_4 = 1u32 << 4;

        // Split into low, middle, high
        let low = biguint_to_scalar(&(val % two_to_126));
        let middle = biguint_to_scalar(&((val >> 126) % two_to_126));
        let high = biguint_to_scalar(&((val >> 252) % two_to_4));

        (low, middle, high)
    }

    /// Evaluates the value in the constraint system and returns the result
    ///
    /// Used only for testing the opposite conversion (bigint -> U256Var)
    pub fn to_bigint<C: RandomizableConstraintSystem>(u256_val: Self, cs: &C) -> BigUint {
        // Evalute the variable assignment in the constraint system
        let low_bigint = scalar_to_biguint(&cs.eval(&u256_val.low.into()));
        let middle_bigint = scalar_to_biguint(&cs.eval(&u256_val.middle.into()));
        let high_bigint = scalar_to_biguint(&cs.eval(&u256_val.high.into()));

        // Recombine the values
        low_bigint + (middle_bigint << 126) + (high_bigint << 252)
    }

    /// Constrains two U256 values to equal one another
    pub fn constrain_equal<CS: RandomizableConstraintSystem>(a: Self, b: Self, cs: &mut CS) {
        // Constrain all bits to be equal
        cs.constrain(a.low - b.low);
        cs.constrain(a.middle - b.middle);
        cs.constrain(a.high - b.high);
    }

    /// Add two U256 variables together
    ///
    /// Takes the result modulo 2^256
    pub fn add<CS: RandomizableConstraintSystem>(lhs: Self, rhs: Self, cs: &mut CS) -> Self {
        // Add the low bits together and take the value modulo 2^128
        let new_low = lhs.low + rhs.low;
        let (carry, low_rem) = div_rem_bigint(new_low, &BIGINT_2_TO_126, cs);

        // Add the middle bits together and take the value modulo 2^128
        let new_middle = lhs.middle + rhs.middle + carry;
        let (carry, middle_rem) = div_rem_bigint(new_middle, &BIGINT_2_TO_126, cs);

        // Finally, add the high values and take the value modulo 2^4
        let new_high = lhs.high + rhs.high + carry;
        let (_, high_rem) = div_rem_bigint(new_high, &BIGINT_2_TO_4, cs);

        Self {
            low: low_rem,
            middle: middle_rem,
            high: high_rem,
        }
    }

    /// Add together a U256 and a bigint
    ///
    /// Same as the implementation above, except that we do not need to allocate variables for the bigint
    pub fn add_bigint<CS: RandomizableConstraintSystem>(
        lhs: Self,
        rhs: BigUint,
        cs: &mut CS,
    ) -> Self {
        // Split the bigint into low, middle, and high bits
        let (rhs_low, rhs_middle, rhs_high) = Self::bigint_to_split_scalars(&rhs);

        // Add the low bits together and take the value modulo 2^128
        let new_low = lhs.low + rhs_low;
        let (carry, low_rem) = div_rem_bigint(new_low, &BIGINT_2_TO_126, cs);

        // Add the middle bits together and take the value modulo 2^128
        let new_middle = lhs.middle + rhs_middle + carry;
        let (carry, middle_rem) = div_rem_bigint(new_middle, &BIGINT_2_TO_126, cs);

        // Finally, add the high values and take the value modulo 2^4
        let new_high = lhs.high + rhs_high + carry;
        let (_, high_rem) = div_rem_bigint(new_high, &BIGINT_2_TO_4, cs);

        Self {
            low: low_rem,
            middle: middle_rem,
            high: high_rem,
        }
    }

    /// Multiply two U256s together
    ///
    /// Takes the result modulo 2^256
    ///
    /// If each U256 is represented as x = low + 2^126 * mid + 2^252 * high, then for x, y
    ///     x * y = (x_low + 2^126 * x_mid + 2^252 * x_high) * (y_low + 2^126 * y_mid + 2^252 * y_high)
    /// Which reduces to
    ///     x * y = x_low * y_low
    ///             + 2^126 * (x_low * y_mid + x_mid * y_low)
    ///             + 2^252 * (x_low * y_high + x_mid * y_mid + x_high * y_low)
    ///             + 2^378 * (x_mid * y_high + x_high * y_mid)
    ///             + 2^504 * (x_high * y_high)
    /// The last two terms (those with 2^378 and 2^504) are both 0 modulo 2^256, so they don't contribute
    pub fn mul<CS: RandomizableConstraintSystem>(lhs: Self, rhs: Self, cs: &mut CS) -> Self {
        // The low value of the multiplication result
        let (carry, low_var) = mul_mod_n(lhs.low, rhs.low, &BIGINT_2_TO_126, cs);

        // Add the middle bit terms
        let (mid_term1_carry, mid_term1_rem) = mul_mod_n(lhs.low, rhs.middle, &BIGINT_2_TO_126, cs);
        let (mid_term2_carry, mid_term2_rem) = mul_mod_n(lhs.middle, rhs.low, &BIGINT_2_TO_126, cs);
        let (additive_carry, middle_var) =
            div_rem_bigint(mid_term1_rem + mid_term2_rem + carry, &BIGINT_2_TO_126, cs);

        let carry = additive_carry + mid_term1_carry + mid_term2_carry;

        // Add the high bit terms
        let (_, high_term1) = mul_mod_n(lhs.low, rhs.high, &BIGINT_2_TO_4, cs);
        let (_, high_term2) = mul_mod_n(lhs.middle, rhs.middle, &BIGINT_2_TO_4, cs);
        let (_, high_term3) = mul_mod_n(lhs.high, rhs.low, &BIGINT_2_TO_4, cs);

        let (_, high_var) = div_rem_bigint(
            high_term1 + high_term2 + high_term3 + carry,
            &BIGINT_2_TO_4,
            cs,
        );

        Self {
            low: low_var,
            middle: middle_var,
            high: high_var,
        }
    }

    /// Multiply a U256 with a bigint
    ///
    /// Similar to the above mul implementation, but we do not need to allocate multiplier
    /// gates for each multiplication
    pub fn mul_bigint<CS: RandomizableConstraintSystem>(
        lhs: Self,
        rhs: BigUint,
        cs: &mut CS,
    ) -> Self {
        // Split the BigUInt into low, middle, and high bits
        let (rhs_low, rhs_middle, rhs_high) = Self::bigint_to_split_scalars(&rhs);

        // The low value of the multiplication result
        let (carry, low_var) = mul_scalar_mod_n(lhs.low, rhs_low, &BIGINT_2_TO_126, cs);

        // Add the middle bit terms
        let (mid_term1_carry, mid_term1_rem) =
            mul_scalar_mod_n(lhs.low, rhs_middle, &BIGINT_2_TO_126, cs);
        let (mid_term2_carry, mid_term2_rem) =
            mul_scalar_mod_n(lhs.middle, rhs_low, &BIGINT_2_TO_126, cs);
        let (additive_carry, middle_var) =
            div_rem_bigint(mid_term1_rem + mid_term2_rem + carry, &BIGINT_2_TO_126, cs);

        let carry = additive_carry + mid_term1_carry + mid_term2_carry;

        // Add the high bit terms
        let (_, high_term1) = mul_scalar_mod_n(lhs.low, rhs_high, &BIGINT_2_TO_4, cs);
        let (_, high_term2) = mul_scalar_mod_n(lhs.middle, rhs_middle, &BIGINT_2_TO_4, cs);
        let (_, high_term3) = mul_scalar_mod_n(lhs.high, rhs_low, &BIGINT_2_TO_4, cs);

        let (_, high_var) = div_rem_bigint(
            high_term1 + high_term2 + high_term3 + carry,
            &BIGINT_2_TO_4,
            cs,
        );

        Self {
            low: low_var,
            middle: middle_var,
            high: high_var,
        }
    }

    /// Take the value stored in the U256 modulo the given value
    pub fn div_rem<CS: RandomizableConstraintSystem>(
        val: U256Var,
        modulus: BigUint,
        cs: &mut CS,
    ) -> (U256Var, U256Var) {
        // Evaluate the U256 to a bigint, compute the quotient and remainder, then
        // implicitly constrain the values to be correct
        let u256_bigint = Self::to_bigint(val, cs);

        let div = &u256_bigint / &modulus;
        let rem = &u256_bigint % &modulus;

        let u256_div = U256Var::from_biguint(&div, cs);
        let u256_rem = U256Var::from_biguint(&rem, cs);

        let div_times_mod = U256Var::mul_bigint(u256_div, modulus, cs);
        let reconstructed_val = U256Var::add(div_times_mod, u256_rem, cs);

        // Constrain this to be equal to the input
        U256Var::constrain_equal(reconstructed_val, val, cs);

        (u256_div, u256_rem)
    }
}

#[cfg(test)]
mod bigint_tests {
    use crypto::fields::biguint_to_scalar;
    use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
    use merlin::Transcript;
    use mpc_bulletproof::{
        r1cs::{Prover, R1CSProof, Verifier},
        BulletproofGens, PedersenGens,
    };
    use num_bigint::BigUint;
    use rand_core::{CryptoRng, OsRng, RngCore};

    use crate::{
        errors::{ProverError, VerifierError},
        test_helpers::bulletproof_prove_and_verify,
        CommitProver, CommitVerifier, SingleProverCircuit,
    };

    use super::U256Var;

    // -------------
    // | Constants |
    // -------------

    /// The seed for the prover/verifier transcripts
    const TRANSCRIPT_SEED: &str = "test";

    // -----------
    // | Helpers |
    // -----------

    /// Samples a random 256-bit bigint
    fn random_biguint<R: RngCore + CryptoRng>(rng: &mut R) -> BigUint {
        let bytes = &mut [0u8; 32];
        rng.fill_bytes(bytes);
        BigUint::from_bytes_le(bytes)
    }

    /// Splits a bigint into high, medium, and low scalars
    fn bigint_to_split_scalars(val: &BigUint) -> (Scalar, Scalar, Scalar) {
        let two_to_126 = 1u128 << 126;
        let two_to_4 = 1u32 << 4;

        // Split into low, middle, high
        let low = biguint_to_scalar(&(val % two_to_126));
        let middle = biguint_to_scalar(&((val >> 126) % two_to_126));
        let high = biguint_to_scalar(&((val >> 252) % two_to_4));

        (low, middle, high)
    }

    // ------------
    // | Circuits |
    // ------------

    /// A witness type reused between the Add and Mul circuits for testing a fan-in 2
    /// fan-out 1 operator
    #[derive(Clone, Debug)]
    struct OperatorWitness {
        // The left hand side of the operator
        pub lhs: BigUint,
        // The right hand side of the operator
        pub rhs: BigUint,
    }

    impl CommitProver for OperatorWitness {
        type CommitType = CommittedOperatorWitness;
        type VarType = OperatorWitnessVar;
        type ErrorType = ();

        fn commit_prover<R: rand_core::RngCore + rand_core::CryptoRng>(
            &self,
            rng: &mut R,
            prover: &mut Prover,
        ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
            let (lhs_low, lhs_mid, lhs_high) = bigint_to_split_scalars(&self.lhs);
            let (rhs_low, rhs_mid, rhs_high) = bigint_to_split_scalars(&self.rhs);

            // Commit individually to the low, middle, and high bit representations
            let (lhs_low_comm, lhs_low_var) = prover.commit(lhs_low, Scalar::random(rng));
            let (lhs_mid_comm, lhs_mid_var) = prover.commit(lhs_mid, Scalar::random(rng));
            let (lhs_high_comm, lhs_high_var) = prover.commit(lhs_high, Scalar::random(rng));

            let (rhs_low_comm, rhs_low_var) = prover.commit(rhs_low, Scalar::random(rng));
            let (rhs_mid_comm, rhs_mid_var) = prover.commit(rhs_mid, Scalar::random(rng));
            let (rhs_high_comm, rhs_high_var) = prover.commit(rhs_high, Scalar::random(rng));

            Ok((
                OperatorWitnessVar {
                    lhs: U256Var::new(lhs_low_var, lhs_mid_var, lhs_high_var),
                    rhs: U256Var::new(rhs_low_var, rhs_mid_var, rhs_high_var),
                },
                CommittedOperatorWitness {
                    lhs_low: lhs_low_comm,
                    lhs_middle: lhs_mid_comm,
                    lhs_high: lhs_high_comm,
                    rhs_low: rhs_low_comm,
                    rhs_middle: rhs_mid_comm,
                    rhs_high: rhs_high_comm,
                },
            ))
        }
    }

    /// A constraint-system allocated witness type for the operator witness
    #[derive(Clone, Debug)]
    struct OperatorWitnessVar {
        /// The left-hand side of the operation
        pub lhs: U256Var,
        /// The right-hand side of the operation
        pub rhs: U256Var,
    }

    /// A committed witness type for the operator witness
    #[derive(Clone, Debug)]
    struct CommittedOperatorWitness {
        /// The low bits of the left-hand operand
        lhs_low: CompressedRistretto,
        /// The middle bits of the left-hand operand
        lhs_middle: CompressedRistretto,
        /// The high bits of the left-hand operand
        lhs_high: CompressedRistretto,
        /// The low bits of the right-hand operand
        rhs_low: CompressedRistretto,
        /// The middle bits of the right-hand operand
        rhs_middle: CompressedRistretto,
        /// The high bits of the right-hand operand
        rhs_high: CompressedRistretto,
    }

    impl CommitVerifier for CommittedOperatorWitness {
        type VarType = OperatorWitnessVar;
        type ErrorType = ();

        fn commit_verifier(
            &self,
            verifier: &mut Verifier,
        ) -> Result<Self::VarType, Self::ErrorType> {
            // Commit to each of the bit representations and then recombine them into the U256 var
            let lhs_low_var = verifier.commit(self.lhs_low);
            let lhs_mid_var = verifier.commit(self.lhs_middle);
            let lhs_high_var = verifier.commit(self.lhs_high);

            let rhs_low_var = verifier.commit(self.rhs_low);
            let rhs_mid_var = verifier.commit(self.rhs_middle);
            let rhs_high_var = verifier.commit(self.rhs_high);

            Ok(OperatorWitnessVar {
                lhs: U256Var::new(lhs_low_var, lhs_mid_var, lhs_high_var),
                rhs: U256Var::new(rhs_low_var, rhs_mid_var, rhs_high_var),
            })
        }
    }

    /// A statement type reused between the Add and Mul circuits for testing a fan-in 2
    /// fan-out 1 operator
    #[derive(Clone, Debug)]
    struct OperatorStatement {
        /// The expected output of applying the operator to the witness
        expected_out: BigUint,
    }

    struct AdderCircuit {}
    impl SingleProverCircuit for AdderCircuit {
        type Statement = OperatorStatement;
        type Witness = OperatorWitness;
        type WitnessCommitment = CommittedOperatorWitness;

        const BP_GENS_CAPACITY: usize = 512;

        fn prove(
            witness: Self::Witness,
            statement: Self::Statement,
            mut prover: Prover,
        ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
            // Commit to the statement variable
            let mut rng = OsRng {};
            let (expected_low, expected_mid, expected_high) =
                bigint_to_split_scalars(&statement.expected_out);
            let (_, expected_low_var) = prover.commit_public(expected_low);
            let (_, expected_mid_var) = prover.commit_public(expected_mid);
            let (_, expected_high_var) = prover.commit_public(expected_high);

            let expected_var = U256Var::new(expected_low_var, expected_mid_var, expected_high_var);

            // Commit to the witness
            let (witness_var, witness_comm) = witness.commit_prover(&mut rng, &mut prover).unwrap();

            // Apply the constraints
            let res = U256Var::add(witness_var.lhs, witness_var.rhs, &mut prover);
            U256Var::constrain_equal(res, expected_var, &mut prover);

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
            // Commit to the statement variable
            let (expected_low, expected_mid, expected_high) =
                bigint_to_split_scalars(&statement.expected_out);
            let expected_low_var = verifier.commit_public(expected_low);
            let expected_mid_var = verifier.commit_public(expected_mid);
            let expected_high_var = verifier.commit_public(expected_high);

            let expected_var = U256Var::new(expected_low_var, expected_mid_var, expected_high_var);

            // Commit to the witness
            let witness_var = witness_commitment.commit_verifier(&mut verifier).unwrap();

            // Apply the constraints
            let res = U256Var::add(witness_var.lhs, witness_var.rhs, &mut verifier);
            U256Var::constrain_equal(res, expected_var, &mut verifier);

            // Verify the proof
            let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
            verifier
                .verify(&proof, &bp_gens)
                .map_err(VerifierError::R1CS)
        }
    }

    struct MulCircuit {}
    impl SingleProverCircuit for MulCircuit {
        type Statement = OperatorStatement;
        type Witness = OperatorWitness;
        type WitnessCommitment = CommittedOperatorWitness;

        const BP_GENS_CAPACITY: usize = 512;

        fn prove(
            witness: Self::Witness,
            statement: Self::Statement,
            mut prover: Prover,
        ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
            // Commit to the statement variable
            let mut rng = OsRng {};
            let (expected_low, expected_mid, expected_high) =
                bigint_to_split_scalars(&statement.expected_out);
            let (_, expected_low_var) = prover.commit_public(expected_low);
            let (_, expected_mid_var) = prover.commit_public(expected_mid);
            let (_, expected_high_var) = prover.commit_public(expected_high);

            let expected_var = U256Var::new(expected_low_var, expected_mid_var, expected_high_var);

            // Commit to the witness
            let (witness_var, witness_comm) = witness.commit_prover(&mut rng, &mut prover).unwrap();

            // Apply the constraints
            let res = U256Var::mul(witness_var.lhs, witness_var.rhs, &mut prover);
            U256Var::constrain_equal(res, expected_var, &mut prover);

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
            // Commit to the statement variable
            let (expected_low, expected_mid, expected_high) =
                bigint_to_split_scalars(&statement.expected_out);
            let expected_low_var = verifier.commit_public(expected_low);
            let expected_mid_var = verifier.commit_public(expected_mid);
            let expected_high_var = verifier.commit_public(expected_high);

            let expected_var = U256Var::new(expected_low_var, expected_mid_var, expected_high_var);

            // Commit to the witness
            let witness_var = witness_commitment.commit_verifier(&mut verifier).unwrap();

            // Apply the constraints
            let res = U256Var::mul(witness_var.lhs, witness_var.rhs, &mut verifier);
            U256Var::constrain_equal(res, expected_var, &mut verifier);

            // Verify the proof
            let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
            verifier
                .verify(&proof, &bp_gens)
                .map_err(VerifierError::R1CS)
        }
    }

    struct DivRemCircuit {}
    impl SingleProverCircuit for DivRemCircuit {
        /// Statement is (modulus, expected_div, expected_rem)
        type Statement = (BigUint, BigUint, BigUint);
        /// Witness is the input to the mod operation
        type Witness = BigUint;
        type WitnessCommitment = (
            CompressedRistretto,
            CompressedRistretto,
            CompressedRistretto,
        );

        const BP_GENS_CAPACITY: usize = 512;

        fn prove(
            witness: Self::Witness,
            statement: Self::Statement,
            mut prover: Prover,
        ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
            // Commit to the statement variable
            let mut rng = OsRng {};

            let (expected_div_low, expected_div_mid, expected_div_high) =
                bigint_to_split_scalars(&statement.1);
            let (_, expected_div_low_var) = prover.commit_public(expected_div_low);
            let (_, expected_div_mid_var) = prover.commit_public(expected_div_mid);
            let (_, expected_div_high_var) = prover.commit_public(expected_div_high);

            let expected_div_var = U256Var::new(
                expected_div_low_var,
                expected_div_mid_var,
                expected_div_high_var,
            );

            let (expected_rem_low, expected_rem_mid, expected_rem_high) =
                bigint_to_split_scalars(&statement.2);
            let (_, expected_rem_low_var) = prover.commit_public(expected_rem_low);
            let (_, expected_rem_mid_var) = prover.commit_public(expected_rem_mid);
            let (_, expected_rem_high_var) = prover.commit_public(expected_rem_high);

            let expected_rem_var = U256Var::new(
                expected_rem_low_var,
                expected_rem_mid_var,
                expected_rem_high_var,
            );

            // Commit to the witness
            let (witness_low, witness_mid, witness_high) = bigint_to_split_scalars(&witness);
            let (wintess_low_comm, witness_low_var) =
                prover.commit(witness_low, Scalar::random(&mut rng));
            let (witness_mid_comm, witness_mid_var) =
                prover.commit(witness_mid, Scalar::random(&mut rng));
            let (witness_high_comm, witness_high_var) =
                prover.commit(witness_high, Scalar::random(&mut rng));

            let witness_var = U256Var::new(witness_low_var, witness_mid_var, witness_high_var);

            // Apply the constraints
            let (res_div, res_rem) = U256Var::div_rem(witness_var, statement.0, &mut prover);
            U256Var::constrain_equal(res_div, expected_div_var, &mut prover);
            U256Var::constrain_equal(res_rem, expected_rem_var, &mut prover);

            // Prove the statement
            let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
            let proof = prover.prove(&bp_gens).map_err(ProverError::R1CS)?;

            Ok((
                (wintess_low_comm, witness_mid_comm, witness_high_comm),
                proof,
            ))
        }

        fn verify(
            witness_commitment: Self::WitnessCommitment,
            statement: Self::Statement,
            proof: R1CSProof,
            mut verifier: Verifier,
        ) -> Result<(), VerifierError> {
            // Commit to the statement
            let (expected_div_low, expected_div_mid, expected_div_high) =
                bigint_to_split_scalars(&statement.1);
            let expected_div_low_var = verifier.commit_public(expected_div_low);
            let expected_div_mid_var = verifier.commit_public(expected_div_mid);
            let expected_div_high_var = verifier.commit_public(expected_div_high);

            let expected_div_var = U256Var::new(
                expected_div_low_var,
                expected_div_mid_var,
                expected_div_high_var,
            );

            let (expected_rem_low, expected_rem_mid, expected_rem_high) =
                bigint_to_split_scalars(&statement.2);
            let expected_rem_low_var = verifier.commit_public(expected_rem_low);
            let expected_rem_mid_var = verifier.commit_public(expected_rem_mid);
            let expected_rem_high_var = verifier.commit_public(expected_rem_high);

            let expected_rem_var = U256Var::new(
                expected_rem_low_var,
                expected_rem_mid_var,
                expected_rem_high_var,
            );

            // Commit to the witness
            let witness_low_var = verifier.commit(witness_commitment.0);
            let witness_mid_var = verifier.commit(witness_commitment.1);
            let witness_high_var = verifier.commit(witness_commitment.2);

            let witness_var = U256Var::new(witness_low_var, witness_mid_var, witness_high_var);

            // Apply the constraints
            let (res_div, res_rem) = U256Var::div_rem(witness_var, statement.0, &mut verifier);
            U256Var::constrain_equal(res_div, expected_div_var, &mut verifier);
            U256Var::constrain_equal(res_rem, expected_rem_var, &mut verifier);

            // Verify the proof
            let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
            verifier
                .verify(&proof, &bp_gens)
                .map_err(VerifierError::R1CS)
        }
    }

    // ---------
    // | Tests |
    // ---------

    /// Tests converting a bigint to a UInt256
    #[test]
    fn test_bigint_to_uint256() {
        let n_tests = 100;
        let mut rng = OsRng {};

        let mut prover_transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        for _ in 0..n_tests {
            // Sample a random biguint and allocate it in the constraint system
            let random_bigint = random_biguint(&mut rng);
            let u256_val = U256Var::from_biguint(&random_bigint, &mut prover);
            let reconstructed_bigint = U256Var::to_bigint(u256_val, &prover);

            assert_eq!(random_bigint, reconstructed_bigint);
        }
    }

    /// Tests adding two values together in the constraint system
    #[test]
    fn test_add_uint256() {
        let n_tests = 10;
        let mut rng = OsRng {};

        for _ in 0..n_tests {
            // Test the adder circuit
            let random_bigint1 = random_biguint(&mut rng);
            let random_bigint2 = random_biguint(&mut rng);

            let exepcted_sum = (&random_bigint1 + &random_bigint2) % (BigUint::from(1u8) << 256);

            let witness = OperatorWitness {
                lhs: random_bigint1,
                rhs: random_bigint2,
            };
            let statement = OperatorStatement {
                expected_out: exepcted_sum,
            };

            let res = bulletproof_prove_and_verify::<AdderCircuit>(witness, statement);
            assert!(res.is_ok());
        }
    }

    /// Tests adding an allocated value and a bigint
    #[test]
    fn test_add_biguint() {
        let n_tests = 100;
        let mut rng = OsRng {};

        let mut prover_transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        for _ in 0..n_tests {
            let random_bigint1 = random_biguint(&mut rng);
            let random_bigint2 = random_biguint(&mut rng);

            let exepcted_sum = (&random_bigint1 + &random_bigint2) % (BigUint::from(1u8) << 256);

            let u256_var = U256Var::from_biguint(&random_bigint1, &mut prover);
            let out_var = U256Var::add_bigint(u256_var, random_bigint2, &mut prover);
            let out_eval = U256Var::to_bigint(out_var, &prover);

            assert_eq!(out_eval, exepcted_sum);
        }
    }

    /// Tests multiplying two values together in the constraint system
    #[test]
    fn test_mul_uint256() {
        let n_tests = 10;
        let mut rng = OsRng {};

        for _ in 0..n_tests {
            // Test the mul circuit
            let random_bigint1 = random_biguint(&mut rng);
            let random_bigint2 = random_biguint(&mut rng);

            let expected_product =
                (&random_bigint1 * &random_bigint2) % (BigUint::from(1u8) << 256);

            let witness = OperatorWitness {
                lhs: random_bigint1,
                rhs: random_bigint2,
            };
            let statement = OperatorStatement {
                expected_out: expected_product,
            };

            let res = bulletproof_prove_and_verify::<MulCircuit>(witness, statement);
            assert!(res.is_ok());
        }
    }

    /// Tests multiplying a U256Var with a BigUint
    #[test]
    fn test_mul_biguint() {
        let n_tests = 100;
        let mut rng = OsRng {};

        let mut prover_transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        for _ in 0..n_tests {
            let random_bigint1 = random_biguint(&mut rng);
            let random_bigint2 = random_biguint(&mut rng);

            let expected_product =
                (&random_bigint1 * &random_bigint2) % (BigUint::from(1u8) << 256);

            let u256_var = U256Var::from_biguint(&random_bigint1, &mut prover);
            let out_var = U256Var::mul_bigint(u256_var, random_bigint2, &mut prover);
            let out_eval = U256Var::to_bigint(out_var, &prover);

            assert_eq!(expected_product, out_eval);
        }
    }

    /// Tests taking a value modulo a random value  
    #[test]
    fn test_mod() {
        let n_tests = 10;
        let mut rng = OsRng {};

        for _ in 0..n_tests {
            let random_bigint1 = random_biguint(&mut rng);
            let random_bigint2 = random_biguint(&mut rng);

            let expected_div = &random_bigint1 / &random_bigint2;
            let expected_rem = &random_bigint1 % &random_bigint2;

            let witness = random_bigint1;
            let statement = (random_bigint2, expected_div, expected_rem);

            let res = bulletproof_prove_and_verify::<DivRemCircuit>(witness, statement);
            assert!(res.is_ok());
        }
    }
}
