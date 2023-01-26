//! Defines fixed point representations within the constraint system, along with
//! arithmetic between fixed-point and native Scalars

use std::ops::Add;

use bigdecimal::ToPrimitive;
use crypto::fields::{biguint_to_scalar, scalar_to_bigdecimal};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use lazy_static::lazy_static;
use mpc_bulletproof::r1cs::{
    LinearCombination, Prover, RandomizableConstraintSystem, Variable, Verifier,
};
use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};

use crate::CommitVerifier;

/// The default fixed point decimal precision in bits
/// i.e. the number of bits allocated to a fixed point's decimal
const DEFAULT_PRECISION: usize = 32;

lazy_static! {
    /// The shift used to generate a scalar representation from a fixed point
    static ref TWO_TO_M: BigUint = BigUint::from(1u8) << DEFAULT_PRECISION;

    /// The shift, converted to a scalar
    static ref TWO_TO_M_SCALAR: Scalar = biguint_to_scalar(&TWO_TO_M);

    /// Compute the constant 2^-M (mod p), so that we may conveniently reduce after
    /// multiplications
    static ref TWO_TO_NEG_M: Scalar = {
        let two_to_m_scalar = biguint_to_scalar(&TWO_TO_M);
        two_to_m_scalar.invert()
    };
}

/// Represents a fixed point number in the constraint system
///
/// For a fixed precision rational $z$, the scalar held by the
/// struct is the scalar representation $z * 2^M$ where M is the
/// fixed-point precision in use
#[derive(Clone, Debug)]
pub struct FixedPointVar {
    /// The underlying scalar representing the fixed point variable
    repr: LinearCombination,
}

/// A commitment to a fixed-precision variable
#[derive(Copy, Clone, Debug)]
pub struct CommittedFixedPointVar {
    /// The underlying scalar representing the fixed point variable
    repr: CompressedRistretto,
}

impl CommitVerifier for CommittedFixedPointVar {
    type VarType = FixedPointVar;
    type ErrorType = ();

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let repr_var = verifier.commit(self.repr);
        Ok(FixedPointVar {
            repr: repr_var.into(),
        })
    }
}

impl FixedPointVar {
    /// Allocate a floating point variable in the constraint system as a witness variable,
    /// represented as a fixed-point variable
    pub fn commit_witness<R: RngCore + CryptoRng>(
        val: f32,
        rng: &mut R,
        prover: &mut Prover,
    ) -> (Self, CommittedFixedPointVar) {
        let shifted_val = val * (2u64.pow(DEFAULT_PRECISION as u32) as f32);
        assert_eq!(
            shifted_val,
            shifted_val.floor(),
            "Given value exceeds precision of constraint system"
        );

        let (fp_comm, fp_var) =
            prover.commit(Scalar::from(shifted_val as u64), Scalar::random(rng));

        (
            Self {
                repr: fp_var.into(),
            },
            CommittedFixedPointVar { repr: fp_comm },
        )
    }

    /// Allocate a floating point variable in the constraint system as a public variable
    /// represented as a fixed-point variable
    pub fn commit_public<CS: RandomizableConstraintSystem>(val: f32, cs: &mut CS) -> Self {
        let shifted_val = val * (2u64.pow(DEFAULT_PRECISION as u32) as f32);
        assert_eq!(
            shifted_val,
            shifted_val.floor(),
            "Given value exceeds precision of constraint system"
        );

        let fp_var = cs.commit_public(Scalar::from(shifted_val as u64));
        Self {
            repr: fp_var.into(),
        }
    }

    /// Evaluate the given fixed point variable in the constraint system and return the underlying
    /// value as a floating point
    ///
    /// Note: not optimized, used mostly for tests
    pub fn eval<CS: RandomizableConstraintSystem>(&self, cs: &CS) -> f32 {
        // Evaluate the scalar into a wide decimal form, shift it, then case
        // to f32
        let eval = scalar_to_bigdecimal(&cs.eval(&self.repr));
        let shifted_eval = &eval / (2f64.powi(DEFAULT_PRECISION as i32));

        // Shift down the precision
        shifted_eval.to_f32().unwrap()
    }

    /// Multiplication cannot be implemented directly via the std::ops trait, because it needs
    /// access to a constraint system
    ///
    /// When we multiply two fixed point variables (say x and y for z = x * y, represented as
    /// x' = x * 2^M);
    /// we get the result x' * y' = x * 2^M * y * 2^M = z' * 2^M,
    /// so we need an extra reduction step in which we multiply the result by 2^-M
    pub fn mul_fixed_point<CS: RandomizableConstraintSystem>(
        &self,
        rhs: &Self,
        cs: &mut CS,
    ) -> FixedPointVar {
        let (_, _, direct_mul) = cs.multiply(self.repr.clone(), rhs.repr.clone());
        Self {
            repr: *TWO_TO_NEG_M * direct_mul,
        }
    }

    /// Multiplication with an integer value
    ///
    /// This needs no reduction step as this is implicitly done by *not* converting the integer to a fixed-point
    /// representation. I.e. instead of taking x * 2^M * y * 2^M * 2^-M, we can just directly
    /// multiply x * 2^M * y
    pub fn mul_integer<L, CS>(&self, rhs: L, cs: &mut CS) -> FixedPointVar
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        let (_, _, direct_mul) = cs.multiply(self.repr.clone(), rhs.into());
        Self {
            repr: direct_mul.into(),
        }
    }
}

impl Add<FixedPointVar> for FixedPointVar {
    type Output = FixedPointVar;

    fn add(self, rhs: FixedPointVar) -> Self::Output {
        Self {
            repr: self.repr + rhs.repr,
        }
    }
}

/// Addition with an integer, requires that we first convert the integer to
/// its fixed point representation
impl Add<Variable> for FixedPointVar {
    type Output = FixedPointVar;

    fn add(self, rhs: Variable) -> Self::Output {
        let rhs_shifted = rhs * *TWO_TO_M_SCALAR;

        Self {
            repr: self.repr + rhs_shifted,
        }
    }
}

#[cfg(test)]
mod fixed_point_tests {
    use bigdecimal::{BigDecimal, Signed};
    use crypto::fields::scalar_to_bigint;
    use curve25519_dalek::scalar::Scalar;
    use merlin::Transcript;
    use mpc_bulletproof::{
        r1cs::{ConstraintSystem, Prover},
        PedersenGens,
    };
    use num_bigint::{BigInt, ToBigInt};
    use rand::{thread_rng, Rng, RngCore};

    use crate::zk_gadgets::fixed_point::DEFAULT_PRECISION;

    use super::FixedPointVar;

    /// Tests that converting to and from f32 works properly
    #[test]
    fn test_repr() {
        let n_tests = 100;
        let mut rng = thread_rng();

        // Create a constraint system and allocate the floating points
        let mut prover_transcript = Transcript::new("test".as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        for _ in 0..n_tests {
            // Generate two random fixed point values
            let fp1 = rng.gen_range(0.0..1000000.);
            let fp1_var = FixedPointVar::commit_public(fp1, &mut prover);

            let fp1_eval = fp1_var.eval(&prover);

            assert_eq!(fp1_eval, fp1);
        }
    }

    /// Tests adding together two fixed point values
    #[test]
    fn test_mul() {
        let n_tests = 100;
        let mut rng = thread_rng();

        // Create a constraint system and allocate the floating points
        let mut prover_transcript = Transcript::new("test".as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        for _ in 0..n_tests {
            // Generate two random fixed point values
            let fp1 = rng.gen_range(0.0..1000000.);
            let fp2 = rng.gen_range(0.0..1000000.);

            let expected_res = fp1 * fp2;

            let fp1_var = FixedPointVar::commit_public(fp1, &mut prover);
            let fp2_var = FixedPointVar::commit_public(fp2, &mut prover);

            let res_var = fp1_var.mul_fixed_point(&fp2_var, &mut prover);
            let res_eval = res_var.eval(&prover);

            assert_eq!(res_eval, expected_res);
        }
    }

    /// Tests the addition of two fixed-point variables
    #[test]
    fn test_add() {
        let n_tests = 100;
        let mut rng = thread_rng();

        // Create a constraint system and allocate the floating points
        let mut prover_transcript = Transcript::new("test".as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        for _ in 0..n_tests {
            // Generate two random fixed point values
            let fp1 = rng.gen_range(0.0..1000000.);
            let fp2 = rng.gen_range(0.0..1000000.);

            // Compute expected res in f64 to ensure we have enough representational capacity
            let expected_res = (fp1 as f64) + (fp2 as f64);

            let mut expected_repr = BigDecimal::try_from(expected_res).unwrap();
            expected_repr = &expected_repr * (BigInt::from(1u8) << DEFAULT_PRECISION);

            let fp1_var = FixedPointVar::commit_public(fp1, &mut prover);
            let fp2_var = FixedPointVar::commit_public(fp2, &mut prover);

            let res_var = fp1_var + fp2_var;

            // Compare the reprs, easier than trying to properly cast down precision to f32
            let res_var_repr = scalar_to_bigint(&prover.eval(&res_var.repr));

            let expected_repr_bigint = expected_repr.to_bigint().unwrap();

            // Computing the actual expected value has some room for floating point mis-precision;
            // as a result we constraint the values to be close
            assert!((res_var_repr - expected_repr_bigint).abs() < BigInt::from(10u8));
        }
    }

    /// Tests multiplying an integer with a fixed point number
    #[test]
    fn test_integer_mul() {
        let n_tests = 100;
        let mut rng = thread_rng();

        // Create a constraint system and allocate the floating points
        let mut prover_transcript = Transcript::new("test".as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        for _ in 0..n_tests {
            // Generate a random fixed point value and a random integer
            let fp1 = rng.gen_range(0.0..1000000.);
            let int = rng.next_u32();

            let expected_res = fp1 * (int as f32);

            let fp_var = FixedPointVar::commit_public(fp1, &mut prover);
            let int_var = prover.commit_public(Scalar::from(int));

            let res_var = fp_var.mul_integer(int_var, &mut prover);
            let res = res_var.eval(&prover);

            // Using floating points as a base comparison loses some precision, especially for large
            // numbers. Instead just check that the floating point error is sufficiently small
            assert!((res - expected_res).abs() / res < 0.001);
        }
    }

    #[test]
    fn test_integer_add() {
        let n_tests = 100;
        let mut rng = thread_rng();

        // Create a constraint system and allocate the floating points
        let mut prover_transcript = Transcript::new("test".as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        for _ in 0..n_tests {
            // Generate a random fixed point value and a random integer
            let fp1 = rng.gen_range(0.0..1000000.);
            let int = rng.next_u32();

            let expected_res = fp1 + (int as f32);

            let fp_var = FixedPointVar::commit_public(fp1, &mut prover);
            let int_var = prover.commit_public(Scalar::from(int));

            let res_var = fp_var + int_var;
            let res = res_var.eval(&prover);

            // Using floating points as a base comparison loses some precision, especially for large
            // numbers. Instead just check that the floating point error is sufficiently small
            assert!((res - expected_res).abs() / res < 0.001);
        }
    }
}
