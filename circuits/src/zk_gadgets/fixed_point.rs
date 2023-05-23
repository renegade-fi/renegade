//! Defines fixed point representations within the constraint system, along with
//! arithmetic between fixed-point and native Scalars

use std::ops::{Add, Mul, Neg, Sub};

use bigdecimal::{BigDecimal, ToPrimitive};
use crypto::fields::{bigint_to_scalar, biguint_to_scalar, scalar_to_bigdecimal, scalar_to_bigint};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use lazy_static::lazy_static;
use mpc_bulletproof::{
    r1cs::{LinearCombination, Prover, RandomizableConstraintSystem, Variable, Verifier},
    r1cs_mpc::{
        MpcLinearCombination, MpcProver, MpcRandomizableConstraintSystem, MpcVariable,
        MultiproverError,
    },
};
use mpc_ristretto::{
    authenticated_ristretto::AuthenticatedCompressedRistretto,
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource,
    mpc_scalar::scalar_to_u64, network::MpcNetwork,
};
use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    errors::MpcError, mpc::SharedFabric, mpc_gadgets::modulo::shift_right, Allocate,
    AuthenticatedLinkableCommitment, CommitSharedProver, CommitVerifier, CommitWitness,
    LinkableCommitment,
};

use super::{arithmetic::DivRemGadget, comparators::EqGadget};

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

// ------------------------------
// | Native Type Implementation |
// ------------------------------

/// Represents a fixed point number not yet allocated in the constraint system
///
/// This is useful for centralizing conversion logic to provide an abstract to_scalar,
/// from_scalar interface to modules that commit to this value
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FixedPoint {
    /// The underlying scalar representing the fixed point variable
    pub(crate) repr: Scalar,
}

impl FixedPoint {
    /// Create a new fixed point representation of the given u64
    pub fn from_integer(val: u64) -> Self {
        let val_shifted = Scalar::from(val) * *TWO_TO_M_SCALAR;
        Self { repr: val_shifted }
    }

    /// Create a new fixed point representation, rounding down to the nearest representable float
    pub fn from_f32_round_down(val: f32) -> Self {
        let shifted_val = val * (2u64.pow(DEFAULT_PRECISION as u32) as f32);
        Self {
            repr: Scalar::from(shifted_val.floor() as u64),
        }
    }

    /// Commit to the fixed point variable as a public input in a given constraint system
    pub fn commit_public<CS: RandomizableConstraintSystem>(&self, cs: &mut CS) -> FixedPointVar {
        let repr = cs.commit_public(self.repr);
        FixedPointVar { repr: repr.into() }
    }

    /// Return the represented value as an f64
    pub fn to_f64(&self) -> f64 {
        let mut dec = BigDecimal::from(scalar_to_bigint(&self.repr));
        dec = &dec / (1u64 << DEFAULT_PRECISION);
        dec.to_f64().unwrap()
    }

    /// Rounds down the given value to an integer and returns the integer representation
    pub fn floor(&self) -> Scalar {
        // Clear the bottom `DEFAULT_PRECISION` bits
        let mut self_bigint = scalar_to_bigint(&self.repr);
        self_bigint >>= DEFAULT_PRECISION;

        bigint_to_scalar(&self_bigint)
    }
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

impl From<u64> for FixedPoint {
    fn from(val: u64) -> Self {
        Self {
            repr: Scalar::from(val),
        }
    }
}

impl From<FixedPoint> for u64 {
    fn from(fp: FixedPoint) -> Self {
        scalar_to_u64(&fp.repr)
    }
}

impl Add<FixedPoint> for FixedPoint {
    type Output = FixedPoint;
    fn add(self, rhs: FixedPoint) -> Self::Output {
        Self {
            repr: self.repr + rhs.repr,
        }
    }
}

impl Add<Scalar> for FixedPoint {
    type Output = FixedPoint;
    fn add(self, rhs: Scalar) -> Self::Output {
        Self {
            repr: self.repr + *TWO_TO_M_SCALAR * rhs,
        }
    }
}

impl Add<FixedPoint> for Scalar {
    type Output = FixedPoint;
    fn add(self, rhs: FixedPoint) -> Self::Output {
        rhs + self
    }
}

impl Mul<Scalar> for FixedPoint {
    type Output = FixedPoint;
    fn mul(self, rhs: Scalar) -> Self::Output {
        Self {
            repr: self.repr * rhs,
        }
    }
}

impl Neg for FixedPoint {
    type Output = FixedPoint;
    fn neg(self) -> Self::Output {
        Self {
            repr: self.repr.neg(),
        }
    }
}

impl Sub<FixedPoint> for FixedPoint {
    type Output = FixedPoint;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: FixedPoint) -> Self::Output {
        self + rhs.neg()
    }
}

impl Sub<Scalar> for FixedPoint {
    type Output = FixedPoint;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Scalar) -> Self::Output {
        self + rhs.neg()
    }
}

impl Sub<FixedPoint> for Scalar {
    type Output = FixedPoint;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: FixedPoint) -> Self::Output {
        self + rhs.neg()
    }
}

impl Serialize for FixedPoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize the value as a floating point
        let mut bigdec = scalar_to_bigdecimal(&self.repr);
        bigdec = &bigdec / (1u64 << DEFAULT_PRECISION);

        serializer.serialize_f32(bigdec.to_f32().unwrap())
    }
}

impl<'de> Deserialize<'de> for FixedPoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let val_f32 = f32::deserialize(deserializer)?;
        Ok(FixedPoint::from(val_f32))
    }
}

impl From<FixedPoint> for LinkableFixedPointCommitment {
    fn from(fp: FixedPoint) -> Self {
        Self {
            repr: LinkableCommitment::new(fp.repr),
        }
    }
}

impl From<LinkableFixedPointCommitment> for FixedPoint {
    fn from(fp: LinkableFixedPointCommitment) -> Self {
        Self { repr: fp.repr.val }
    }
}

/// A fixed point commitment that may be linked across proofs
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkableFixedPointCommitment {
    /// The underlying scalar representation
    pub(crate) repr: LinkableCommitment,
}

impl CommitWitness for LinkableFixedPointCommitment {
    type VarType = FixedPointVar;
    type CommitType = CommittedFixedPoint;
    type ErrorType = ();

    fn commit_witness<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (var, comm) = self.repr.commit_witness(rng, prover).unwrap();
        Ok((
            FixedPointVar { repr: var.into() },
            CommittedFixedPoint { repr: comm },
        ))
    }
}

// ---------------------------------------------
// | Constraint System Variable Implementation |
// ---------------------------------------------

/// For a fixed precision rational $z$, the scalar held by the
/// struct is the scalar representation $z * 2^M$ where M is the
/// fixed-point precision in use
#[derive(Clone, Debug)]
pub struct FixedPointVar {
    /// The underlying scalar representing the fixed point variable
    pub(crate) repr: LinearCombination,
}

/// A commitment to a fixed-precision variable
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommittedFixedPoint {
    /// The underlying scalar representing the fixed point variable
    pub repr: CompressedRistretto,
}

impl CommitWitness for FixedPoint {
    type VarType = FixedPointVar;
    type CommitType = CommittedFixedPoint;
    type ErrorType = ();

    fn commit_witness<R: RngCore + CryptoRng>(
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

    /// Computes the closest integral value less than the given fixed point variable and
    /// constraints this value to be correctly computed.
    ///
    /// Returns the integer representation directly
    pub fn floor<CS: RandomizableConstraintSystem>(&self, cs: &mut CS) -> Variable {
        // Floor div by the scaling factor
        let (div, _) = DivRemGadget::<DEFAULT_PRECISION>::div_rem(
            self.repr.clone(),
            *TWO_TO_M_SCALAR * Variable::One(),
            cs,
        );

        div
    }

    /// Constrain two fixed point variables to equal one another
    pub fn constraint_equal<CS: RandomizableConstraintSystem>(
        &self,
        rhs: FixedPointVar,
        cs: &mut CS,
    ) {
        cs.constrain(self.repr.clone() - rhs.repr);
    }

    /// Return a boolean indicating whether two fixed point variables are equal
    ///
    /// 1 represents true, 0 is false
    pub fn equal<CS: RandomizableConstraintSystem>(
        &self,
        rhs: FixedPointVar,
        cs: &mut CS,
    ) -> Variable {
        EqGadget::eq(self.repr.clone(), rhs.repr, cs)
    }

    /// Constrain a fixed point variable to equal an integer
    pub fn constraint_equal_integer<CS: RandomizableConstraintSystem>(
        &self,
        rhs: Variable,
        cs: &mut CS,
    ) {
        let fixed_point_repr = Self::shift_integer(rhs);
        self.constraint_equal(fixed_point_repr, cs);
    }

    /// Return a boolean indicating whether a fixed point and integer are equal
    ///
    /// 1 represents true, 0 is false
    pub fn equal_integer<CS: RandomizableConstraintSystem>(
        &self,
        rhs: Variable,
        cs: &mut CS,
    ) -> Variable {
        let fixed_point_repr = Self::shift_integer(rhs);
        self.equal(fixed_point_repr, cs)
    }

    /// Shift an integer into its fixed point representation
    fn shift_integer(val: Variable) -> FixedPointVar {
        FixedPointVar {
            repr: *TWO_TO_M_SCALAR * val,
        }
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

/// Addition with an integer on the left hand side
impl Add<FixedPointVar> for Variable {
    type Output = FixedPointVar;

    fn add(self, rhs: FixedPointVar) -> Self::Output {
        // Commutative
        rhs + self
    }
}

/// Negation of a fixed point variable, simply negate the underlying representation
impl Neg for FixedPointVar {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            repr: self.repr * Scalar::one().neg(),
        }
    }
}

/// Subtraction of a fixed point variable with another
impl Sub<FixedPointVar> for FixedPointVar {
    type Output = FixedPointVar;

    fn sub(self, rhs: FixedPointVar) -> Self::Output {
        Self {
            repr: self.repr - rhs.repr,
        }
    }
}

/// Subtraction of a fixed point variable from an integer
impl Sub<FixedPointVar> for Variable {
    type Output = FixedPointVar;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: FixedPointVar) -> Self::Output {
        self + rhs.neg()
    }
}

/// Subtraction of an integer from a fixed point variable
impl Sub<Variable> for FixedPointVar {
    type Output = Self;

    fn sub(self, rhs: Variable) -> Self::Output {
        // Convert the integer to a fixed point variable
        let shifted_rhs = *TWO_TO_M_SCALAR * rhs;
        Self {
            repr: self.repr - shifted_rhs,
        }
    }
}

// -------------------------------
// | Shared Value Implementation |
// -------------------------------

/// A fixed point variable that has been allocated in an MPC fabric
#[derive(Debug)]
pub struct AuthenticatedFixedPoint<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The underlying scalar representing the fixed point variable
    pub(crate) repr: AuthenticatedScalar<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> AuthenticatedFixedPoint<N, S> {
    /// Create an authenticated fixed-point variable from a given scalar integer
    pub fn from_integer(val: Scalar, fabric: SharedFabric<N, S>) -> Self {
        // Shift the scalar before allocating
        let val_shifted = val * *TWO_TO_M_SCALAR;
        Self {
            repr: fabric.borrow_fabric().allocate_public_scalar(val_shifted),
        }
    }
}

/// Removes the requirement of the generics `N` and `S` to be `Clone`
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Clone for AuthenticatedFixedPoint<N, S> {
    fn clone(&self) -> Self {
        Self {
            repr: self.repr.clone(),
        }
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> From<AuthenticatedScalar<N, S>>
    for AuthenticatedFixedPoint<N, S>
{
    fn from(val: AuthenticatedScalar<N, S>) -> Self {
        Self { repr: val }
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> AuthenticatedFixedPoint<N, S> {
    /// Create an authenticated fixed point variable from a public floating point
    pub fn from_public_f32(val: f32, fabric: SharedFabric<N, S>) -> Self {
        // Shift the floating point into its scalar representation
        let shifted_val = val * (2u64.pow(DEFAULT_PRECISION as u32) as f32);
        assert_eq!(
            shifted_val,
            shifted_val.floor(),
            "Given value exceeds precision of constraint system"
        );

        let scalar_repr = Scalar::from(shifted_val as u64);
        Self {
            repr: fabric.borrow_fabric().allocate_public_scalar(scalar_repr),
        }
    }

    /// Cast the fixed point to an integer by shifting right by the fixed-point fractional precision
    pub fn as_integer(
        &self,
        fabric: SharedFabric<N, S>,
    ) -> Result<AuthenticatedScalar<N, S>, MpcError> {
        shift_right::<DEFAULT_PRECISION, N, S>(&self.repr, fabric)
    }
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

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Mul<&AuthenticatedFixedPoint<N, S>>
    for &AuthenticatedFixedPoint<N, S>
{
    type Output = AuthenticatedFixedPoint<N, S>;

    fn mul(self, rhs: &AuthenticatedFixedPoint<N, S>) -> Self::Output {
        // Multiply representations directly then reduce
        let res_repr = self.repr.clone() * rhs.repr.clone();
        AuthenticatedFixedPoint {
            repr: *TWO_TO_NEG_M * res_repr,
        }
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Mul<&AuthenticatedScalar<N, S>>
    for &AuthenticatedFixedPoint<N, S>
{
    type Output = AuthenticatedFixedPoint<N, S>;

    fn mul(self, rhs: &AuthenticatedScalar<N, S>) -> Self::Output {
        AuthenticatedFixedPoint {
            repr: self.repr.clone() * rhs,
        }
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Mul<&AuthenticatedFixedPoint<N, S>>
    for AuthenticatedScalar<N, S>
{
    type Output = AuthenticatedFixedPoint<N, S>;

    fn mul(self, rhs: &AuthenticatedFixedPoint<N, S>) -> Self::Output {
        AuthenticatedFixedPoint {
            repr: self * rhs.repr.clone(),
        }
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Add<&AuthenticatedFixedPoint<N, S>>
    for &AuthenticatedFixedPoint<N, S>
{
    type Output = AuthenticatedFixedPoint<N, S>;

    fn add(self, rhs: &AuthenticatedFixedPoint<N, S>) -> Self::Output {
        AuthenticatedFixedPoint {
            repr: self.repr.clone() + rhs.repr.clone(),
        }
    }
}

/// Add a scalar to a fixed-point
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Add<&AuthenticatedScalar<N, S>>
    for &AuthenticatedFixedPoint<N, S>
{
    type Output = AuthenticatedFixedPoint<N, S>;

    fn add(self, rhs: &AuthenticatedScalar<N, S>) -> Self::Output {
        // Shift the integer
        let rhs_shifted = *TWO_TO_M_SCALAR * rhs;
        AuthenticatedFixedPoint {
            repr: self.repr.clone() + rhs_shifted,
        }
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Add<&AuthenticatedFixedPoint<N, S>>
    for &AuthenticatedScalar<N, S>
{
    type Output = AuthenticatedFixedPoint<N, S>;

    fn add(self, rhs: &AuthenticatedFixedPoint<N, S>) -> Self::Output {
        rhs + self
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Neg for &AuthenticatedFixedPoint<N, S> {
    type Output = AuthenticatedFixedPoint<N, S>;

    fn neg(self) -> Self::Output {
        AuthenticatedFixedPoint {
            repr: self.repr.clone().neg(),
        }
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Sub<&AuthenticatedFixedPoint<N, S>>
    for &AuthenticatedFixedPoint<N, S>
{
    type Output = AuthenticatedFixedPoint<N, S>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: &AuthenticatedFixedPoint<N, S>) -> Self::Output {
        self + &rhs.neg()
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Sub<&AuthenticatedScalar<N, S>>
    for &AuthenticatedFixedPoint<N, S>
{
    type Output = AuthenticatedFixedPoint<N, S>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: &AuthenticatedScalar<N, S>) -> Self::Output {
        self + &rhs.neg()
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Sub<&AuthenticatedFixedPoint<N, S>>
    for &AuthenticatedScalar<N, S>
{
    type Output = AuthenticatedFixedPoint<N, S>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: &AuthenticatedFixedPoint<N, S>) -> Self::Output {
        self + &rhs.neg()
    }
}

// ------------------------------------------------
// | Multiprover Constraint System Implementation |
// ------------------------------------------------

/// Represents a fixed point variable that has been allocated in an MPC network and
/// committed to in a multi-prover constraint system
#[derive(Debug)]
pub struct AuthenticatedFixedPointVar<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The underlying scalar representing the fixed point variable
    pub(crate) repr: MpcLinearCombination<N, S>,
}

impl<'a, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>>
    AuthenticatedFixedPointVar<N, S>
{
    /// Constrain two authenticated fixed point variables to equal one another
    pub fn constrain_equal<CS: MpcRandomizableConstraintSystem<'a, N, S>>(
        &self,
        rhs: &Self,
        cs: &mut CS,
    ) {
        cs.constrain(self.repr.clone() - rhs.repr.clone());
    }

    /// Constrain a fixed point variable to equal a native field element
    pub fn constrain_equal_integer<CS: MpcRandomizableConstraintSystem<'a, N, S>>(
        &self,
        rhs: &MpcVariable<N, S>,
        cs: &mut CS,
    ) {
        // Shift the integer
        let shifted_rhs = *TWO_TO_M_SCALAR * rhs;
        cs.constrain(self.repr.clone() - shifted_rhs);
    }
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

impl<'a, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>>
    AuthenticatedFixedPointVar<N, S>
{
    /// Multiply with another fixed point variable
    ///
    /// We cannot implement the `Mul` trait directly, because the variables need access
    /// to their constraint system
    pub fn mul_fixed_point<CS: MpcRandomizableConstraintSystem<'a, N, S>>(
        &self,
        rhs: &Self,
        cs: &mut CS,
    ) -> Result<Self, MultiproverError> {
        let (_, _, res_repr) = cs.multiply(&self.repr, &rhs.repr)?;
        Ok(Self {
            repr: *TWO_TO_NEG_M * res_repr,
        })
    }

    /// Multiply a fixed-point variable with a native integer
    pub fn mul_integer<L, CS>(&self, rhs: L, cs: &mut CS) -> Result<Self, MultiproverError>
    where
        L: Into<MpcLinearCombination<N, S>>,
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
    {
        let (_, _, res_repr) = cs.multiply(&self.repr, &rhs.into())?;

        Ok(Self {
            repr: res_repr.into(),
        })
    }
}

impl<'a, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>>
    Add<&'a AuthenticatedFixedPointVar<N, S>> for &'a AuthenticatedFixedPointVar<N, S>
{
    type Output = AuthenticatedFixedPointVar<N, S>;

    fn add(self, rhs: &'a AuthenticatedFixedPointVar<N, S>) -> Self::Output {
        AuthenticatedFixedPointVar {
            repr: self.repr.clone() + rhs.repr.clone(),
        }
    }
}

/// Addition with field elements (integer representation)
impl<
        'a,
        N: 'a + MpcNetwork + Send,
        S: 'a + SharedValueSource<Scalar>,
        L: Into<MpcLinearCombination<N, S>>,
    > Add<L> for &'a AuthenticatedFixedPointVar<N, S>
{
    type Output = AuthenticatedFixedPointVar<N, S>;

    fn add(self, rhs: L) -> Self::Output {
        // Shift the integer into a fixed point representation
        let rhs_shifted = *TWO_TO_M_SCALAR * rhs.into();
        AuthenticatedFixedPointVar {
            repr: self.repr.clone() + rhs_shifted,
        }
    }
}

/// Addition with field elements, fixed-point on the rhs
impl<'a, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>>
    Add<&'a AuthenticatedFixedPointVar<N, S>> for &'a MpcLinearCombination<N, S>
{
    type Output = AuthenticatedFixedPointVar<N, S>;

    fn add(self, rhs: &'a AuthenticatedFixedPointVar<N, S>) -> Self::Output {
        rhs + self.clone()
    }
}

impl<'a, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>> Neg
    for &'a AuthenticatedFixedPointVar<N, S>
{
    type Output = AuthenticatedFixedPointVar<N, S>;

    fn neg(self) -> Self::Output {
        AuthenticatedFixedPointVar {
            repr: self.repr.clone() * Scalar::one().neg(),
        }
    }
}

impl<'a, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>>
    Sub<&'a AuthenticatedFixedPointVar<N, S>> for &'a AuthenticatedFixedPointVar<N, S>
{
    type Output = AuthenticatedFixedPointVar<N, S>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: &'a AuthenticatedFixedPointVar<N, S>) -> Self::Output {
        self + &rhs.neg()
    }
}

impl<
        'a,
        N: 'a + MpcNetwork + Send,
        S: 'a + SharedValueSource<Scalar>,
        L: Into<MpcLinearCombination<N, S>>,
    > Sub<L> for &'a AuthenticatedFixedPointVar<N, S>
{
    type Output = AuthenticatedFixedPointVar<N, S>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: L) -> Self::Output {
        self + rhs.into().neg()
    }
}

impl<'a, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>>
    Sub<&'a AuthenticatedFixedPointVar<N, S>> for &'a MpcLinearCombination<N, S>
{
    type Output = AuthenticatedFixedPointVar<N, S>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: &'a AuthenticatedFixedPointVar<N, S>) -> Self::Output {
        self + &rhs.neg()
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
            AuthenticatedFixedPointVar {
                repr: shared_var.into(),
            },
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

/// Represents a fixed point value that has been allocated in an MPC fabric and may be shared across
/// proofs
#[derive(Debug)]
pub struct AuthenticatedLinkableFixedPointCommitment<
    N: MpcNetwork + Send,
    S: SharedValueSource<Scalar>,
> {
    /// The underlying scalar representing the fixed point variable
    pub(crate) repr: AuthenticatedLinkableCommitment<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Clone
    for AuthenticatedLinkableFixedPointCommitment<N, S>
{
    fn clone(&self) -> Self {
        Self {
            repr: self.repr.clone(),
        }
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> From<AuthenticatedFixedPoint<N, S>>
    for AuthenticatedLinkableFixedPointCommitment<N, S>
{
    fn from(fp: AuthenticatedFixedPoint<N, S>) -> Self {
        Self {
            repr: AuthenticatedLinkableCommitment::new(fp.repr),
        }
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod fixed_point_tests {
    use bigdecimal::{BigDecimal, FromPrimitive, Signed};
    use crypto::fields::{scalar_to_bigdecimal, scalar_to_bigint};
    use curve25519_dalek::scalar::Scalar;
    use integration_helpers::mpc_network::field::get_ristretto_group_modulus;
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

    /// Tests subtracting one fixed point variable from another
    #[test]
    fn test_sub() {
        let n_tests = 100;
        let mut rng = thread_rng();

        // Create a constraint system and allocate the floating points
        let mut prover_transcript = Transcript::new("test".as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        for _ in 0..n_tests {
            // Generate a random fixed point value and a random integer
            let fp1 = rng.gen_range(0.0..1000000.);
            let fp2 = rng.gen_range(0.0..1000000.);

            let expected_res = fp1 - fp2;

            let fp1_var = FixedPointVar::commit_public(fp1, &mut prover);
            let fp2_var = FixedPointVar::commit_public(fp2, &mut prover);

            let res_var = fp1_var - fp2_var;
            let res_repr = scalar_to_bigdecimal(&prover.eval(&res_var.repr));

            let mut expected_repr = &BigDecimal::from_f32(expected_res).unwrap()
                * (BigInt::from(1u8) << DEFAULT_PRECISION);
            if expected_repr < BigDecimal::from_i8(0).unwrap() {
                expected_repr = (get_ristretto_group_modulus().to_bigint().unwrap()
                    - expected_repr.to_bigint().unwrap())
                .into();
            }

            // Check the representation directly, this is less prone to error
            assert!((&res_repr - expected_repr) / &res_repr < BigDecimal::from_f32(0.01).unwrap())
        }
    }
}
