mod poseidon;

use ark_ff::fields::{Fp256, MontBackend, MontConfig};
use circuits::{scalar_to_bigint, scalar_to_biguint};
use curve25519_dalek::scalar::Scalar;
use num_bigint::{BigInt, BigUint};

/// Defines a custom Arkworks field with the same modulus as the Dalek Ristretto group
///
/// This is necessary for testing against Arkworks, otherwise the values will not be directly comparable
#[derive(MontConfig)]
#[modulus = "7237005577332262213973186563042994240857116359379907606001950938285454250989"]
#[generator = "2"]
pub(crate) struct TestFieldConfig;
pub(crate) type TestField = Fp256<MontBackend<TestFieldConfig, 4>>;

/**
 * Helpers
 */

/// Converts a dalek scalar to an arkworks ff element
fn scalar_to_prime_field(a: &Scalar) -> TestField {
    Fp256::from(scalar_to_biguint(a))
}

/// Converts a nested vector of Dalek scalars to arkworks field elements
fn convert_scalars_nested_vec(a: &Vec<Vec<Scalar>>) -> Vec<Vec<TestField>> {
    let mut res = Vec::with_capacity(a.len());
    for row in a.iter() {
        let mut row_res = Vec::with_capacity(row.len());
        for val in row.iter() {
            row_res.push(scalar_to_prime_field(val))
        }

        res.push(row_res);
    }

    res
}

/// Convert an arkworks prime field element to a bigint
fn felt_to_bigint(element: &TestField) -> BigInt {
    let felt_biguint = Into::<BigUint>::into(*element);
    felt_biguint.into()
}

/// Compares a Dalek Scalar to an Arkworks field element
fn compare_scalar_to_felt(scalar: &Scalar, felt: &TestField) -> bool {
    scalar_to_bigint(scalar).eq(&felt_to_bigint(felt))
}
