use ark_ff::fields::{Fp256, MontBackend, MontConfig};
use circuits::{bigint_to_scalar, scalar_to_bigint, scalar_to_biguint};
use curve25519_dalek::scalar::Scalar;
use mpc_ristretto::{
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource,
    mpc_scalar::scalar_to_u64, network::MpcNetwork,
};
use num_bigint::{BigInt, BigUint};

pub mod arithmetic;
pub mod bits;
pub mod comparators;
pub mod modulo;
pub mod poseidon;

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
pub(crate) fn scalar_to_prime_field(a: &Scalar) -> TestField {
    Fp256::from(scalar_to_biguint(a))
}

pub(crate) fn prime_field_to_scalar(a: &TestField) -> Scalar {
    bigint_to_scalar(&felt_to_bigint(a))
}

/// Converts a nested vector of Dalek scalars to arkworks field elements
pub(crate) fn convert_scalars_nested_vec(a: &Vec<Vec<Scalar>>) -> Vec<Vec<TestField>> {
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
pub(crate) fn felt_to_bigint(element: &TestField) -> BigInt {
    let felt_biguint = Into::<BigUint>::into(*element);
    felt_biguint.into()
}

/// Compares a Dalek Scalar to an Arkworks field element
pub(crate) fn compare_scalar_to_felt(scalar: &Scalar, felt: &TestField) -> bool {
    scalar_to_bigint(scalar).eq(&felt_to_bigint(felt))
}

pub(crate) fn check_equal<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    x: &AuthenticatedScalar<N, S>,
    expected: u64,
) -> Result<(), String> {
    if x.to_scalar().ne(&Scalar::from(expected)) {
        return Err(format!(
            "Expected: {:?}, got {:?}",
            expected,
            scalar_to_u64(&x.to_scalar())
        ));
    }

    Ok(())
}

pub(crate) fn check_equal_vec<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    x: &[AuthenticatedScalar<N, S>],
    expected: &[u64],
) -> Result<(), String> {
    if x.len() != expected.len() {
        return Err(format!(
            "expected result has length different from given result; {:?} vs {:?}",
            expected.len(),
            x.len()
        ));
    }
    let x_u64 = x
        .iter()
        .map(|val| scalar_to_u64(&val.to_scalar()))
        .collect::<Vec<_>>();

    for i in 0..x.len() {
        if x_u64[i].ne(&expected[i]) {
            return Err(
                format!(
                    "Vectors differ in position {:?}: expected element {:?}, got {:?}\nFull Expected Vec: {:?}\nFull Result Vec: {:?}",
                    i, expected[i], x_u64[i], expected, x_u64
                )
            );
        }
    }

    Ok(())
}
