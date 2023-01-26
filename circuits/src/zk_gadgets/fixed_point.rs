//! Defines fixed point representations within the constraint system, along with
//! arithmetic between fixed-point and native Scalars

use std::ops::Add;

use bigdecimal::ToPrimitive;
use crypto::fields::{biguint_to_scalar, scalar_to_bigdecimal};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use lazy_static::lazy_static;
use mpc_bulletproof::{
    r1cs::{LinearCombination, Prover, RandomizableConstraintSystem, Variable, Verifier},
    r1cs_mpc::{MpcProver, MpcVariable},
};
use mpc_ristretto::{
    authenticated_ristretto::AuthenticatedCompressedRistretto,
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource,
    mpc_scalar::scalar_to_u64, network::MpcNetwork,
};
use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    errors::MpcError, mpc::SharedFabric, Allocate, CommitProver, CommitSharedProver, CommitVerifier,
};

/// The default fixed point decimal precision in bits
/// i.e. the number of bits allocated to a fixed point's decimal
pub(crate) const DEFAULT_PRECISION: usize = 32;

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

/// Represents a fixed point number not yet allocated in the constraint system
///
/// This is useful for centralizing conversion logic to provide an abstract to_scalar,
/// from_scalar interface to modules that commit to this value
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixedPoint {
    /// The underlying scalar representing the fixed point variable
    pub(crate) repr: Scalar,
}

impl From<f32> for FixedPoint {
    fn from(val: f32) -> Self {
        let shifted_val = val * (2u64.pow(DEFAULT_PRECISION as u32) as f32);
        assert_eq!(
            shifted_val,
            shifted_val.floor(),
            "Given value exceeds precision of constraint system"
        );

        Self {
            repr: Scalar::from(shifted_val as u64),
        }
    }
}
impl From<Scalar> for FixedPoint {
    fn from(scalar: Scalar) -> Self {
        Self { repr: scalar }
    }
}

impl From<FixedPoint> for Scalar {
    fn from(fp: FixedPoint) -> Self {
        fp.repr
    }
}

impl From<FixedPoint> for u64 {
    fn from(fp: FixedPoint) -> Self {
        scalar_to_u64(&fp.repr)
    }
}

/// For a fixed precision rational $z$, the scalar held by the
/// struct is the scalar representation $z * 2^M$ where M is the
/// fixed-point precision in use
#[derive(Clone, Debug)]
pub struct FixedPointVar {
    /// The underlying scalar representing the fixed point variable
    pub(crate) repr: LinearCombination,
}

/// A commitment to a fixed-precision variable
#[derive(Copy, Clone, Debug)]
pub struct CommittedFixedPoint {
    /// The underlying scalar representing the fixed point variable
    pub(crate) repr: CompressedRistretto,
}

impl CommitProver for FixedPoint {
    type VarType = FixedPointVar;
    type CommitType = CommittedFixedPoint;
    type ErrorType = ();

    fn commit_prover<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (comm, var) = prover.commit(self.repr, Scalar::random(rng));

        Ok((
            FixedPointVar { repr: var.into() },
            CommittedFixedPoint { repr: comm },
        ))
    }
}

impl CommitVerifier for CommittedFixedPoint {
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
    ) -> (Self, CommittedFixedPoint) {
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
            CommittedFixedPoint { repr: fp_comm },
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

/// A fixed point variable that has been allocated in an MPC fabric
#[derive(Clone, Debug)]
pub struct AuthenticatedFixedPoint<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The underlying scalar representing the fixed point variable
    pub(crate) repr: AuthenticatedScalar<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Allocate<N, S> for FixedPoint {
    type SharedType = AuthenticatedFixedPoint<N, S>;
    type ErrorType = MpcError;

    fn allocate(
        &self,
        owning_party: u64,
        fabric: SharedFabric<N, S>,
    ) -> Result<Self::SharedType, Self::ErrorType> {
        let shared_value = fabric
            .borrow_fabric()
            .allocate_private_scalar(owning_party, self.repr)
            .map_err(|err| MpcError::SharingError(err.to_string()))?;
        Ok(AuthenticatedFixedPoint { repr: shared_value })
    }
}

/// Represents a fixed point variable that has been allocated in an MPC network and
/// committed to in a multi-prover constraint system
#[derive(Debug)]
pub struct AuthenticatedFixedPointVar<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The underlying scalar representing the fixed point variable
    pub(crate) repr: MpcVariable<N, S>,
}

/// Explicit clone implementation to remove the bounds on generics N, S to be `Clone`
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Clone
    for AuthenticatedFixedPointVar<N, S>
{
    fn clone(&self) -> Self {
        Self {
            repr: self.repr.clone(),
        }
    }
}

/// Represents a commitment to a fixed point variable that has been allocated in a multi-prover
/// constraint system
#[derive(Debug)]
pub struct AuthenticatedCommittedFixedPoint<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The underlying scalar representing the fixed point variable
    pub(crate) repr: AuthenticatedCompressedRistretto<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Clone
    for AuthenticatedCommittedFixedPoint<N, S>
{
    fn clone(&self) -> Self {
        Self {
            repr: self.repr.clone(),
        }
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> CommitSharedProver<N, S> for FixedPoint {
    type SharedVarType = AuthenticatedFixedPointVar<N, S>;
    type CommitType = AuthenticatedCommittedFixedPoint<N, S>;
    type ErrorType = MpcError;

    fn commit<R: RngCore + CryptoRng>(
        &self,
        owning_party: u64,
        rng: &mut R,
        prover: &mut MpcProver<N, S>,
    ) -> Result<(Self::SharedVarType, Self::CommitType), Self::ErrorType> {
        let blinder = Scalar::random(rng);
        let (shared_comm, shared_var) = prover
            .commit(owning_party, self.repr, blinder)
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        Ok((
            AuthenticatedFixedPointVar { repr: shared_var },
            AuthenticatedCommittedFixedPoint { repr: shared_comm },
        ))
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> CommitVerifier
    for AuthenticatedCommittedFixedPoint<N, S>
{
    type VarType = FixedPointVar;
    type ErrorType = MpcError;

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let opened_value = self
            .repr
            .open_and_authenticate()
            .map_err(|err| MpcError::OpeningError(err.to_string()))?
            .value();
        let repr = verifier.commit(opened_value);

        Ok(FixedPointVar { repr: repr.into() })
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
