//! Groups gadget definitions for arithmetic on (possibly twisted) Edwards curves

use mpc_bulletproof::r1cs::RandomizableConstraintSystem;
use num_bigint::BigUint;

use super::nonnative::{FieldMod, NonNativeElementVar};

/// Represents a point on a (possibly twisted) Edwards curve
///
/// We do not use the extended twisted Edwards coordinates of
/// Hisil et al. (https://eprint.iacr.org/2008/522.pdf) and instead
/// use the standard Edwards representation and addition formula.
///
/// Below M = field multiplication, D = field doubling, I = field inversion
///
/// This is done because the extended coordinates are designed to remove
/// the need to compute inverses and instead compute more multiplications
/// over the field 9M + 2D (11 multiplications) in the projective coordinates.
/// We are concerned with the resultant number of *constraints* which is reduced
/// by allowing inverses (which are computed outside the circuit and implicitly
/// constrained via a single multiplication). This gives us the 5M + 2I which is
/// an equivalent number of constraints to 7M
#[derive(Clone, Debug)]
pub struct EdwardsPoint {
    /// The x coordinate of the point
    x: NonNativeElementVar,
    /// The y coordinate of the point
    y: NonNativeElementVar,
}

impl EdwardsPoint {
    /// Create a new EdwardsPoint from affine coordinates that have been allocated in the
    /// constraint system
    pub fn new(x: NonNativeElementVar, y: NonNativeElementVar) -> Self {
        Self { x, y }
    }

    /// Create a new EdwardsPoint from affine coordinates represented by `BigUint`s
    pub fn new_from_bigints<CS: RandomizableConstraintSystem>(
        x: BigUint,
        y: BigUint,
        field_mod: FieldMod,
        cs: &mut CS,
    ) -> Self {
        let x_nonnative = NonNativeElementVar::from_bigint(x, field_mod.clone(), cs);
        let y_nonnative = NonNativeElementVar::from_bigint(y, field_mod, cs);

        Self {
            x: x_nonnative,
            y: y_nonnative,
        }
    }

    /// Evaluate the point in the constraint system to get the affine coordinates as BigUints
    pub fn get_affine_coordinates<CS: RandomizableConstraintSystem>(
        &self,
        cs: &CS,
    ) -> (BigUint, BigUint) {
        let x_bigint = self.x.as_bigint(cs);
        let y_bigint = self.y.as_bigint(cs);

        (x_bigint, y_bigint)
    }
}

/// Represents a twisted Edwards curve and holds the curve parameterization. We instantiate a
/// twisted Edwards curve to perform operations on `EdwardsPoint`s within a constraint
/// system.
///
/// An (twisted) Edwards curve over a finite field is the set of (x, y) points such that
///     ax^2 + y^2 = 1 + dx^2y^2
///
/// Note that if a = 1, the curve is a standard (no twist) Edwards curve
#[derive(Clone, Debug)]
pub struct TwistedEdwardsCurve {
    /// The "twist" parameter `a` in the curve
    pub a: BigUint,
    /// The radial deformation parameter `d` in the curve, controls how much
    /// the radius of the curve is warped
    pub d: BigUint,
}

impl TwistedEdwardsCurve {
    /// Create a new instance of a twisted edwards curve from the curve parameters
    pub fn new(a: BigUint, d: BigUint) -> Self {
        Self { a, d }
    }

    /// Add together two Edwards points
    ///
    /// Uses the Edwards addition formula defined in https://eprint.iacr.org/2008/013.pdf
    /// i.e.
    ///     x_3 = (x_1 * y_2 + y_1 * x_2) / (1 + d * x_1 * x_2 * y_1 * y_2)
    ///     y_3 = (y_1 * y_2 - a * x_1 * x_2) / (1 - d * x_1 * x_2 * y_1 * y_2)
    pub fn add_points<CS: RandomizableConstraintSystem>(
        &self,
        lhs: &EdwardsPoint,
        rhs: &EdwardsPoint,
        cs: &mut CS,
    ) -> EdwardsPoint {
        // Compute x_3
        let x1y2 = NonNativeElementVar::mul(&lhs.x, &rhs.y, cs);
        let x2y1 = NonNativeElementVar::mul(&lhs.y, &rhs.x, cs);
        let x1x2y1y2 = NonNativeElementVar::mul(&x1y2, &x2y1, cs);
        let dx1x2y1y2 = NonNativeElementVar::mul_bigint(&x1x2y1y2, &self.d, cs);

        let denom_x3 = NonNativeElementVar::add_bigint(&dx1x2y1y2, &BigUint::from(1u8), cs);
        let num_x3 = NonNativeElementVar::add(&x1y2, &x2y1, cs);
        let x3 = NonNativeElementVar::mul(&num_x3, &NonNativeElementVar::invert(&denom_x3, cs), cs);

        // Compute y3
        let y1y2 = NonNativeElementVar::mul(&lhs.y, &rhs.y, cs);
        let x1x2 = NonNativeElementVar::mul(&lhs.x, &rhs.x, cs);
        let ax1x2 = NonNativeElementVar::mul_bigint(&x1x2, &self.a, cs);
        let numerator = NonNativeElementVar::subtract(&y1y2, &ax1x2, cs);

        let denom_term_inv = NonNativeElementVar::additive_inverse(&dx1x2y1y2, cs);
        let denom = NonNativeElementVar::add_bigint(&denom_term_inv, &BigUint::from(1u8), cs);
        let denom_inv = NonNativeElementVar::invert(&denom, cs);
        let y3 = NonNativeElementVar::mul(&numerator, &denom_inv, cs);

        EdwardsPoint { x: x3, y: y3 }
    }
}

#[cfg(test)]
mod edwards_tests {
    use ark_ec::{
        models::twisted_edwards::TECurveConfig, twisted_edwards::Affine as TEAffine, CurveGroup,
    };
    use ark_ed25519::{EdwardsParameters, Fr as Ed25519Scalar};
    use crypto::fields::prime_field_to_biguint;
    use merlin::Transcript;
    use mpc_bulletproof::{
        r1cs::{Prover, RandomizableConstraintSystem},
        PedersenGens,
    };
    use num_bigint::BigUint;
    use rand_core::{CryptoRng, OsRng, RngCore};

    use crate::zk_gadgets::nonnative::FieldMod;

    use super::{EdwardsPoint, TwistedEdwardsCurve};

    const TRANSCRIPT_SEED: &str = "test";

    // -----------
    // | Helpers |
    // -----------

    /// Create a representation of ed25519 in the constrain system
    fn create_ed25519_repr() -> TwistedEdwardsCurve {
        let a_bigint = prime_field_to_biguint(&EdwardsParameters::COEFF_A);
        let d_bigint = prime_field_to_biguint(&EdwardsParameters::COEFF_D);
        TwistedEdwardsCurve::new(a_bigint, d_bigint)
    }

    /// Multiply a scalar by the ed25519 basepoint defined in:
    /// https://www.rfc-editor.org/rfc/rfc7748
    fn ed25519_basepoint_mul(scalar: BigUint) -> TEAffine<EdwardsParameters> {
        let basepoint = EdwardsParameters::GENERATOR;
        (basepoint * Ed25519Scalar::from(scalar)).into_affine()
    }

    /// Sample a random point on ed25519 in the prime-order group generated by
    /// the basepoint defined in: https://www.rfc-editor.org/rfc/rfc7748
    fn ed25519_random_point<R: RngCore + CryptoRng>(rng: &mut R) -> TEAffine<EdwardsParameters> {
        // Generate random bytes to fill a BigUint
        let mut bytes = vec![0u8; 32];
        rng.fill_bytes(&mut bytes);
        let random_bigint = BigUint::from_bytes_le(&bytes);

        // Cast to a field element and multiply with the basepoint
        ed25519_basepoint_mul(random_bigint)
    }

    /// Convert an arkworks ed25519 point into one allocated in a constraint system
    fn ed25519_to_nonnative_edwards<CS: RandomizableConstraintSystem>(
        point: TEAffine<EdwardsParameters>,
        cs: &mut CS,
    ) -> EdwardsPoint {
        let x_bigint = prime_field_to_biguint(&point.x);
        let y_bigint = prime_field_to_biguint(&point.y);

        let modulus = (BigUint::from(1u8) << 255) - 19u8;
        let field_mod = FieldMod::new(modulus, true /* is_prime */);

        EdwardsPoint::new_from_bigints(x_bigint, y_bigint, field_mod, cs)
    }

    /// Assert that an Arkworks point and a EdwardsPoint from the local gadget are equal
    fn assert_points_equal<CS: RandomizableConstraintSystem>(
        expected: TEAffine<EdwardsParameters>,
        res: EdwardsPoint,
        cs: &CS,
    ) {
        let expected_x1 = prime_field_to_biguint(&expected.x);
        let expected_y1 = prime_field_to_biguint(&expected.y);

        let res_coords = res.get_affine_coordinates(cs);

        assert_eq!((expected_x1, expected_y1), res_coords);
    }

    // ---------
    // | Tests |
    // ---------

    /// Test adding two points together in a constraint system
    #[test]
    fn test_point_addition() {
        // Sample a pair of points on the Arkworks implementation of ed25519
        // and compute the expected result
        let n_tests = 50;
        let mut rng = OsRng {};

        // Create a constraint system to allocate the points within
        let mut prover_transcript = Transcript::new(&TRANSCRIPT_SEED.as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        // Construct the curve
        let curve = create_ed25519_repr();

        for _ in 0..n_tests {
            let pt1 = ed25519_random_point(&mut rng);
            let pt2 = ed25519_random_point(&mut rng);

            let expected = (pt1 + pt2).into_affine();

            // Allocate the points
            let pt1_allocated = ed25519_to_nonnative_edwards(pt1, &mut prover);
            let pt2_allocated = ed25519_to_nonnative_edwards(pt2, &mut prover);

            // Add the points together and check the result
            let res = curve.add_points(&pt1_allocated, &pt2_allocated, &mut prover);
            assert_points_equal(expected, res, &prover);
        }
    }
}
