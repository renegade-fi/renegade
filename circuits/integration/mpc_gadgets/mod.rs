use crypto::fields::{
    prime_field_to_bigint, scalar_to_bigint, scalar_to_prime_field, DalekRistrettoField,
};
use curve25519_dalek::scalar::Scalar;
use mpc_ristretto::{
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource,
    mpc_scalar::scalar_to_u64, network::MpcNetwork,
};

pub mod arithmetic;
pub mod bits;
pub mod comparators;
pub mod modulo;
pub mod poseidon;

/**
 * Helpers
 */

/// Converts a nested vector of Dalek scalars to arkworks field elements
pub(crate) fn convert_scalars_nested_vec(a: &Vec<Vec<Scalar>>) -> Vec<Vec<DalekRistrettoField>> {
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

/// Compares a Dalek Scalar to an Arkworks field element
pub(crate) fn compare_scalar_to_felt(scalar: &Scalar, felt: &DalekRistrettoField) -> bool {
    scalar_to_bigint(scalar).eq(&prime_field_to_bigint(felt))
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
