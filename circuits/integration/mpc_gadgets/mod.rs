use curve25519_dalek::scalar::Scalar;
use mpc_ristretto::{
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource,
    mpc_scalar::scalar_to_u64, network::MpcNetwork,
};

pub mod bits;
pub mod comparators;
pub mod modulo;

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
