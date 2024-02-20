//! Defines fixed point representations within the constraint system, along with
//! arithmetic between fixed-point and native Scalars
#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use std::ops::{Add, Mul, Neg, Sub};

use ark_ff::{BigInteger, Field, PrimeField};
use bigdecimal::{BigDecimal, ToPrimitive};
use circuit_macros::circuit_type;
use constants::{AuthenticatedScalar, Scalar, ScalarField, PROTOCOL_FEE};
use lazy_static::lazy_static;
use mpc_relation::{errors::CircuitError, traits::Circuit, Variable};
use num_bigint::BigUint;
use renegade_crypto::fields::{
    bigint_to_scalar, biguint_to_scalar, scalar_to_bigdecimal, scalar_to_bigint, scalar_to_u64,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    scalar,
    traits::{
        BaseType, CircuitBaseType, CircuitVarType, MpcBaseType, MpcType,
        MultiproverCircuitBaseType, SecretShareBaseType, SecretShareType, SecretShareVarType,
    },
    Fabric, PlonkCircuit, SCALAR_ONE,
};

/// The default fixed point decimal precision in bits
/// i.e. the number of bits allocated to a fixed point's decimal
pub const DEFAULT_FP_PRECISION: usize = 32;

lazy_static! {
    /// The shift used to generate a scalar representation from a fixed point
    pub static ref TWO_TO_M: BigUint = BigUint::from(1u8) << DEFAULT_FP_PRECISION;

    /// The shift, converted to a scalar
    pub static ref TWO_TO_M_SCALAR: ScalarField = biguint_to_scalar(&TWO_TO_M).inner();

    /// Compute the constant 2^-M (mod p), so that we may conveniently reduce after
    /// multiplications
    pub static ref TWO_TO_NEG_M: ScalarField = TWO_TO_M_SCALAR.inverse().unwrap();

    /// A fixed point representation of the global protocol fee
    pub static ref PROTOCOL_FEE_FP: FixedPoint = FixedPoint::from_f64_round_down(PROTOCOL_FEE);
}

// -----------
// | Helpers |
// -----------

/// Shift a given Scalar by M bits to the right
pub fn right_shift_scalar_by_m(scalar: Scalar) -> Scalar {
    // Directly modify the underlying `BigInt` representation
    let mut inner = scalar.inner().into_bigint();
    inner.divn(DEFAULT_FP_PRECISION as u32);

    Scalar::new(ScalarField::new(inner))
}

// ------------------------------
// | Native Type Implementation |
// ------------------------------

/// Represents a fixed point number not yet allocated in the constraint system
///
/// This is useful for centralizing conversion logic to provide an abstract
/// to_scalar, from_scalar interface to modules that commit to this value
#[circuit_type(singleprover_circuit, mpc, multiprover_circuit, secret_share)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FixedPoint {
    /// The underlying scalar representing the fixed point variable
    pub repr: Scalar,
}

impl FixedPoint {
    /// Whether the represented fixed point is negative
    pub fn is_negative(&self) -> bool {
        let neg_threshold = ScalarField::MODULUS_MINUS_ONE_DIV_TWO;
        self.repr.inner() > neg_threshold.into()
    }

    /// Return the absolute value of the fixed point
    pub fn abs(&self) -> Self {
        if self.is_negative() {
            self.neg()
        } else {
            *self
        }
    }

    /// Create a new fixed point representation of the given u64
    pub fn from_integer(val: u64) -> Self {
        let val_shifted = Scalar::from(val) * scalar!(*TWO_TO_M_SCALAR);
        Self { repr: val_shifted }
    }

    /// Create a new fixed point representation, rounding down to the nearest
    /// representable float
    pub fn from_f32_round_down(val: f32) -> Self {
        Self::from_f64_round_down(val as f64)
    }

    /// Create a new fixed point representation, rounding up to the nearest
    /// representable float
    pub fn from_f64_round_down(val: f64) -> Self {
        let shifted_val = val * (2u64.pow(DEFAULT_FP_PRECISION as u32) as f64);
        Self { repr: Scalar::from(shifted_val.floor() as u64) }
    }

    /// Return the represented value as an f64
    pub fn to_f64(&self) -> f64 {
        let dec = BigDecimal::from(scalar_to_bigint(&self.abs().repr));
        let result = &dec / (1u64 << DEFAULT_FP_PRECISION);

        let neg = self.is_negative();
        result.to_f64().map(|x| if neg { -x } else { x }).unwrap()
    }

    /// Return the represented value as an f32
    pub fn to_f32(&self) -> f32 {
        self.to_f64() as f32
    }

    /// Rounds down the given value to an integer and returns the integer
    /// representation
    pub fn floor(&self) -> Scalar {
        // Clear the bottom `DEFAULT_FP_PRECISION` bits
        let mut self_bigint = scalar_to_bigint(&self.repr);
        self_bigint >>= DEFAULT_FP_PRECISION;

        bigint_to_scalar(&self_bigint)
    }
}

impl From<f32> for FixedPoint {
    fn from(val: f32) -> Self {
        let shifted_val = val * (2u64.pow(DEFAULT_FP_PRECISION as u32) as f32);
        assert_eq!(
            shifted_val,
            shifted_val.floor(),
            "Given value exceeds precision of constraint system"
        );

        Self { repr: Scalar::from(shifted_val as u64) }
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
        Self { repr: Scalar::from(val) }
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
        Self { repr: self.repr + rhs.repr }
    }
}

impl Add<Scalar> for FixedPoint {
    type Output = FixedPoint;
    fn add(self, rhs: Scalar) -> Self::Output {
        Self { repr: self.repr + scalar!(*TWO_TO_M_SCALAR) * rhs }
    }
}

impl Add<FixedPoint> for Scalar {
    type Output = FixedPoint;
    fn add(self, rhs: FixedPoint) -> Self::Output {
        rhs + self
    }
}

impl Mul<FixedPoint> for FixedPoint {
    type Output = FixedPoint;

    fn mul(self, rhs: FixedPoint) -> Self::Output {
        // Multiply representations directly then reduce
        let res_repr = self.repr * rhs.repr;
        Self { repr: right_shift_scalar_by_m(res_repr) }
    }
}

impl Mul<Scalar> for FixedPoint {
    type Output = FixedPoint;
    fn mul(self, rhs: Scalar) -> Self::Output {
        Self { repr: self.repr * rhs }
    }
}

impl Neg for FixedPoint {
    type Output = FixedPoint;
    fn neg(self) -> Self::Output {
        Self { repr: self.repr.neg() }
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
        bigdec = &bigdec / (1u64 << DEFAULT_FP_PRECISION);

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

// ---------------------------------------------
// | Constraint System Variable Implementation |
// ---------------------------------------------

/// A commitment to a fixed-precision variable
impl Copy for FixedPointVar {}
impl FixedPointVar {
    /// Evaluate the given fixed point variable in the constraint system and
    /// return the underlying value as a floating point
    ///
    /// Note: not optimized, used mostly for tests
    pub fn eval_f64(&self, circuit: &PlonkCircuit) -> f64 {
        // Evaluate the scalar into a wide decimal form, shift it, then cast
        // to f64
        self.eval(circuit).to_f64()
    }

    // --------------
    // | Arithmetic |
    // --------------

    /// Add one fixed point variable to another
    pub fn add<C: Circuit<ScalarField>>(&self, rhs: &Self, cs: &mut C) -> Self {
        let repr = cs.add(self.repr, rhs.repr).unwrap();
        Self { repr }
    }

    /// Add an integer to a fixed point variable
    pub fn add_integer<C: Circuit<ScalarField>>(&self, rhs: Variable, cs: &mut C) -> Self {
        let repr = cs.add_with_coeffs(self.repr, rhs, &SCALAR_ONE, &TWO_TO_M_SCALAR).unwrap();
        Self { repr }
    }

    /// Subtract a fixed point variable from another
    pub fn sub<C: Circuit<ScalarField>>(&self, rhs: &Self, cs: &mut C) -> Self {
        let repr = cs.sub(self.repr, rhs.repr).unwrap();
        Self { repr }
    }

    /// Subtract an integer from a fixed point variable
    pub fn sub_integer<C: Circuit<ScalarField>>(&self, rhs: Variable, cs: &mut C) -> Self {
        let repr = cs.add_with_coeffs(self.repr, rhs, &SCALAR_ONE, &TWO_TO_M_SCALAR.neg()).unwrap();

        Self { repr }
    }

    /// Subtract a fixed point variable from an integer
    pub fn sub_from_integer<C: Circuit<ScalarField>>(&self, rhs: Variable, cs: &mut C) -> Self {
        let neg_one = SCALAR_ONE.neg();
        let repr = cs.add_with_coeffs(self.repr, rhs, &neg_one, &TWO_TO_M_SCALAR).unwrap();
        Self { repr }
    }

    /// Negate a fixed point variable
    pub fn neg<C: Circuit<ScalarField>>(&self, cs: &mut C) -> Self {
        let repr = cs.mul_constant(self.repr, &(-SCALAR_ONE)).unwrap();

        Self { repr }
    }

    /// TODO: Implement truncation logic and fixed-point * fixed-point if
    /// necessary

    /// Multiplication with an integer value
    ///
    /// This needs no reduction step as this is implicitly done by *not*
    /// converting the integer to a fixed-point representation. I.e. instead
    /// of taking x * 2^M * y * 2^M * 2^-M, we can just directly multiply x
    /// * 2^M * y
    pub fn mul_integer<C: Circuit<ScalarField>>(
        &self,
        rhs: Variable,
        cs: &mut C,
    ) -> Result<FixedPointVar, CircuitError> {
        let repr = cs.mul(self.repr, rhs)?;
        Ok(FixedPointVar { repr })
    }
}

impl From<AuthenticatedScalar> for AuthenticatedFixedPoint {
    fn from(val: AuthenticatedScalar) -> Self {
        Self { repr: val }
    }
}

impl Mul<&AuthenticatedScalar> for &AuthenticatedFixedPoint {
    type Output = AuthenticatedFixedPoint;

    fn mul(self, rhs: &AuthenticatedScalar) -> Self::Output {
        AuthenticatedFixedPoint { repr: self.repr.clone() * rhs }
    }
}

impl Mul<&AuthenticatedFixedPoint> for AuthenticatedScalar {
    type Output = AuthenticatedFixedPoint;

    fn mul(self, rhs: &AuthenticatedFixedPoint) -> Self::Output {
        AuthenticatedFixedPoint { repr: self * rhs.repr.clone() }
    }
}

impl Add<&AuthenticatedFixedPoint> for &AuthenticatedFixedPoint {
    type Output = AuthenticatedFixedPoint;

    fn add(self, rhs: &AuthenticatedFixedPoint) -> Self::Output {
        AuthenticatedFixedPoint { repr: self.repr.clone() + rhs.repr.clone() }
    }
}

/// Add a scalar to a fixed-point
impl Add<&AuthenticatedScalar> for &AuthenticatedFixedPoint {
    type Output = AuthenticatedFixedPoint;

    fn add(self, rhs: &AuthenticatedScalar) -> Self::Output {
        // Shift the integer
        let rhs_shifted = scalar!(*TWO_TO_M_SCALAR) * rhs;
        AuthenticatedFixedPoint { repr: self.repr.clone() + rhs_shifted }
    }
}

impl Add<&AuthenticatedFixedPoint> for &AuthenticatedScalar {
    type Output = AuthenticatedFixedPoint;

    fn add(self, rhs: &AuthenticatedFixedPoint) -> Self::Output {
        rhs + self
    }
}

impl Neg for &AuthenticatedFixedPoint {
    type Output = AuthenticatedFixedPoint;

    fn neg(self) -> Self::Output {
        AuthenticatedFixedPoint { repr: self.repr.clone().neg() }
    }
}

impl Sub<&AuthenticatedFixedPoint> for &AuthenticatedFixedPoint {
    type Output = AuthenticatedFixedPoint;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: &AuthenticatedFixedPoint) -> Self::Output {
        self + &rhs.neg()
    }
}

impl Sub<&AuthenticatedScalar> for &AuthenticatedFixedPoint {
    type Output = AuthenticatedFixedPoint;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: &AuthenticatedScalar) -> Self::Output {
        self + &rhs.neg()
    }
}

impl Sub<&AuthenticatedFixedPoint> for &AuthenticatedScalar {
    type Output = AuthenticatedFixedPoint;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: &AuthenticatedFixedPoint) -> Self::Output {
        self + &rhs.neg()
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod fixed_point_tests {

    use ark_mpc::{PARTY0, PARTY1};
    use rand::{thread_rng, Rng};
    use test_helpers::mpc_network::execute_mock_mpc;

    use super::*;

    // -----------
    // | Helpers |
    // -----------

    /// The tolerance to use for equality checks with f64
    const F64_TOLERANCE: f64 = 1e-6;
    /// The tolerance used for equality checks on multiplications which may
    /// differ from floating points by larger margins
    ///
    /// We require our result to be within 1% of the true value
    const F64_MUL_TOLERANCE: f64 = 0.01;

    /// Check that a given f64 is within some tolerance of another
    fn check_within_tolerance(val: f64, expected: f64, tolerance: f64) {
        assert!(
            (val - expected).abs() < tolerance,
            "Expected {} to be within {} of {}",
            val,
            tolerance,
            expected
        );
    }

    /// Check that a given f64 differs from another by less than some percent
    /// tolerance
    fn check_within_fractional_tolerance(val: f64, expected: f64, tolerance: f64) {
        let diff = (val - expected).abs();
        let diff_ratio = diff / expected;

        assert!(
            diff_ratio < tolerance,
            "Expected {} to be within {} of {}",
            val,
            diff_ratio,
            expected
        );
    }

    // ----------------------------
    // | Native Fixed Point Tests |
    // ----------------------------

    /// Tests conversion f64 <--> FixedPoint
    #[test]
    fn test_repr() {
        let mut rng = thread_rng();
        let val: f64 = rng.gen();

        let fp = FixedPoint::from_f64_round_down(val);
        let recovered = fp.to_f64();

        check_within_tolerance(val, recovered, F64_TOLERANCE);
    }

    /// Tests addition with `FixedPoint` and with `Scalar`
    #[test]
    fn test_add() {
        let mut rng = thread_rng();
        let (fp1, fp2) = rng.gen();
        let int: u32 = rng.gen();

        let fixed1 = FixedPoint::from_f64_round_down(fp1);
        let fixed2 = FixedPoint::from_f64_round_down(fp2);
        let integer = Scalar::from(int);

        let res1 = fixed1 + fixed2;
        let res2 = fixed1 + integer;

        let expected1 = fp1 + fp2;
        let expected2 = fp1 + (int as f64);

        check_within_tolerance(res1.to_f64(), expected1, F64_TOLERANCE);
        check_within_tolerance(res2.to_f64(), expected2, F64_TOLERANCE);
    }

    /// Tests subtraction with `FixedPoint` and with `Scalar`
    #[test]
    fn test_sub() {
        let mut rng = thread_rng();
        let (fp1, fp2) = rng.gen();
        let int: u32 = rng.gen();

        let fixed1 = FixedPoint::from_f64_round_down(fp1);
        let fixed2 = FixedPoint::from_f64_round_down(fp2);
        let integer = Scalar::from(int);

        let res1 = fixed1 - fixed2;
        let res2 = fixed1 - integer;

        let expected1 = fp1 - fp2;
        let expected2 = fp1 - (int as f64);

        check_within_tolerance(res1.to_f64(), expected1, F64_TOLERANCE);
        check_within_tolerance(res2.to_f64(), expected2, F64_TOLERANCE);
    }

    /// Tests multiplication with `FixedPoint` and with `Scalar`
    #[test]
    fn test_mul() {
        let mut rng = thread_rng();
        let (fp1, fp2) = rng.gen();
        let int: u32 = rng.gen();

        let fixed1 = FixedPoint::from_f32_round_down(fp1);
        let fixed2 = FixedPoint::from_f32_round_down(fp2);
        let integer = Scalar::from(int);

        let res1 = fixed1 * fixed2;
        let res2 = fixed1 * integer;

        let expected1 = fp1 * fp2;
        let expected2 = fp1 * (int as f32);

        check_within_fractional_tolerance(res1.to_f64(), expected1 as f64, F64_MUL_TOLERANCE);
        check_within_fractional_tolerance(res2.to_f64(), expected2 as f64, F64_MUL_TOLERANCE);
    }

    // ---------------------------------------
    // | Constraint System Fixed Point Tests |
    // ---------------------------------------

    /// Tests the eval method in the constraint system
    #[test]
    fn test_eval() {
        let mut rng = thread_rng();
        let val: f64 = rng.gen();

        let fp = FixedPoint::from_f64_round_down(val);

        let mut cs = PlonkCircuit::new_turbo_plonk();
        let fp_var = fp.create_witness(&mut cs);
        let eval = fp_var.eval(&cs);

        assert_eq!(fp, eval);
    }

    /// Tests addition in a constraint system
    #[test]
    fn test_add_circuit() {
        let mut rng = thread_rng();
        let (fp1, fp2) = rng.gen();
        let int: u32 = rng.gen();

        let mut cs = PlonkCircuit::new_turbo_plonk();

        let fixed1 = FixedPoint::from_f64_round_down(fp1).create_witness(&mut cs);
        let fixed2 = FixedPoint::from_f64_round_down(fp2).create_witness(&mut cs);
        let integer = Scalar::from(int).create_witness(&mut cs);

        let res1 = fixed1.add(&fixed2, &mut cs);
        let res2 = fixed1.add_integer(integer, &mut cs);

        let expected1 = fp1 + fp2;
        let expected2 = fp1 + (int as f64);

        check_within_tolerance(res1.eval(&cs).to_f64(), expected1, F64_TOLERANCE);
        check_within_tolerance(res2.eval(&cs).to_f64(), expected2, F64_TOLERANCE);
    }

    /// Tests subtraction in a constraint system
    #[test]
    fn test_sub_circuit() {
        let mut rng = thread_rng();
        let (fp1, fp2) = rng.gen();
        let int: u32 = rng.gen();

        let mut cs = PlonkCircuit::new_turbo_plonk();

        let fixed1 = FixedPoint::from_f64_round_down(fp1).create_witness(&mut cs);
        let fixed2 = FixedPoint::from_f64_round_down(fp2).create_witness(&mut cs);
        let integer = Scalar::from(int).create_witness(&mut cs);

        let res1 = fixed1.sub(&fixed2, &mut cs);
        let res2 = fixed1.sub_integer(integer, &mut cs);

        let expected1 = fp1 - fp2;
        let expected2 = fp1 - (int as f64);

        check_within_tolerance(res1.eval(&cs).to_f64(), expected1, F64_TOLERANCE);
        check_within_tolerance(res2.eval(&cs).to_f64(), expected2, F64_TOLERANCE);
    }

    /// Tests multiplication in a circuit
    ///
    /// TODO: Test fp x fp multiplication
    #[test]
    fn test_mul_circuit() {
        let mut rng = thread_rng();
        let fp1 = rng.gen();
        let int: u32 = rng.gen();

        let mut cs = PlonkCircuit::new_turbo_plonk();

        let fixed1 = FixedPoint::from_f32_round_down(fp1).create_witness(&mut cs);
        let integer = Scalar::from(int).create_witness(&mut cs);

        let res = fixed1.mul_integer(integer, &mut cs).unwrap();
        let expected = fp1 * (int as f32);

        check_within_fractional_tolerance(
            res.eval(&cs).to_f64(),
            expected as f64,
            F64_MUL_TOLERANCE,
        );
    }

    // -------------------------
    // | MPC Fixed Point Tests |
    // -------------------------

    /// Tests opening a shared fixed point variable
    #[tokio::test]
    async fn test_open_eval() {
        let mut rng = thread_rng();
        let fp = rng.gen();

        let fixed = FixedPoint::from_f64_round_down(fp);

        let (res, _) = execute_mock_mpc(move |fabric| async move {
            let shared = fixed.allocate(PARTY0, &fabric);
            let open = shared.open_and_authenticate().await.unwrap();

            open.to_f64()
        })
        .await;

        check_within_tolerance(res, fp, F64_TOLERANCE);
    }

    /// Tests addition in an MPC
    #[tokio::test]
    async fn test_add_mpc() {
        let mut rng = thread_rng();
        let (fp1, fp2) = rng.gen();
        let int: u32 = rng.gen();

        let fixed1 = FixedPoint::from_f64_round_down(fp1);
        let fixed2 = FixedPoint::from_f64_round_down(fp2);
        let integer = Scalar::from(int);

        let ((res1, res2), _) = execute_mock_mpc(move |fabric| async move {
            let fp1 = fixed1.allocate(PARTY0, &fabric);
            let fp2 = fixed2.allocate(PARTY1, &fabric);
            let int = integer.allocate(PARTY0, &fabric);

            let res1 = &fp1 + &fp2;
            let res2 = &fp1 + &int;

            (
                res1.open_and_authenticate().await.unwrap().to_f64(),
                res2.open_and_authenticate().await.unwrap().to_f64(),
            )
        })
        .await;

        let expected1 = fp1 + fp2;
        let expected2 = fp1 + (int as f64);

        check_within_tolerance(res1, expected1, F64_TOLERANCE);
        check_within_tolerance(res2, expected2, F64_TOLERANCE);
    }

    /// Tests subtraction in an MPC
    #[tokio::test]
    async fn test_sub_mpc() {
        let mut rng = thread_rng();
        let (fp1, fp2) = rng.gen();
        let int: u32 = rng.gen();

        let fixed1 = FixedPoint::from_f64_round_down(fp1);
        let fixed2 = FixedPoint::from_f64_round_down(fp2);
        let integer = Scalar::from(int);

        let ((res1, res2), _) = execute_mock_mpc(move |fabric| async move {
            let fp1 = fixed1.allocate(PARTY0, &fabric);
            let fp2 = fixed2.allocate(PARTY1, &fabric);
            let int = integer.allocate(PARTY0, &fabric);

            let res1 = &fp1 - &fp2;
            let res2 = &fp1 - &int;

            (
                res1.open_and_authenticate().await.unwrap().to_f64(),
                res2.open_and_authenticate().await.unwrap().to_f64(),
            )
        })
        .await;

        let expected1 = fp1 - fp2;
        let expected2 = fp1 - (int as f64);

        check_within_tolerance(res1, expected1, F64_TOLERANCE);
        check_within_tolerance(res2, expected2, F64_TOLERANCE);
    }

    /// Tests multiplication in an MPC
    ///
    /// TODO: Test fp x fp multiplication
    #[tokio::test]
    async fn test_mul_mpc() {
        let mut rng = thread_rng();
        let fp = rng.gen();
        let int: u32 = rng.gen();

        let fixed = FixedPoint::from_f64_round_down(fp);
        let integer = Scalar::from(int);

        let (res, _) = execute_mock_mpc(move |fabric| async move {
            let fp = fixed.allocate(PARTY0, &fabric);
            let int = integer.allocate(PARTY0, &fabric);

            let res = &fp * &int;
            res.open_and_authenticate().await.unwrap().to_f64()
        })
        .await;

        let expected = fp * (int as f64);
        check_within_fractional_tolerance(res, expected, F64_MUL_TOLERANCE);
    }
}
