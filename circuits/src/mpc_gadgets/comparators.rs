//! Groups logic around arithemtic comparator circuits

use std::ops::Neg;

use curve25519_dalek::scalar::Scalar;
use mpc_ristretto::{
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource, network::MpcNetwork,
};

use crate::{errors::MpcError, mpc::SharedFabric};

use super::modulo::truncate;

/// Implements the comparator a < 0
///
/// D represents is the bitlength of the input
pub fn less_than_zero<const D: usize, N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    a: &AuthenticatedScalar<N, S>,
    fabric: SharedFabric<N, S>,
) -> Result<AuthenticatedScalar<N, S>, MpcError> {
    Ok(truncate(a, D - 1, fabric)?.neg())
}

/// Implements the comparator a == 0
///
/// D represents the bitlength of the input
#[allow(unused_variables)]
pub fn eq_zero<const D: usize, N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    a: &AuthenticatedScalar<N, S>,
    fabric: SharedFabric<N, S>,
) -> Result<AuthenticatedScalar<N, S>, MpcError> {
    // TODO: Implement K-ary OR primitive, then build this circuit
    Err(MpcError::NotImplemented)
}

/// Implements the comparator a < b
///
/// D represents the bitlength of a and b
pub fn less_than<const D: usize, N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    a: &AuthenticatedScalar<N, S>,
    b: &AuthenticatedScalar<N, S>,
    fabric: SharedFabric<N, S>,
) -> Result<AuthenticatedScalar<N, S>, MpcError> {
    less_than_zero::<D, _, _>(&(a - b), fabric)
}

/// Implements the comparator a <= b
///
/// D represents the bitlength of a and b
pub fn less_than_equal<const D: usize, N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    a: &AuthenticatedScalar<N, S>,
    b: &AuthenticatedScalar<N, S>,
    fabric: SharedFabric<N, S>,
) -> Result<AuthenticatedScalar<N, S>, MpcError> {
    Ok(Scalar::one() - greater_than::<D, _, _>(a, b, fabric)?)
}

/// Implements the comparator a > b
///
/// D represents the bitlength of a and b
pub fn greater_than<const D: usize, N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    a: &AuthenticatedScalar<N, S>,
    b: &AuthenticatedScalar<N, S>,
    fabric: SharedFabric<N, S>,
) -> Result<AuthenticatedScalar<N, S>, MpcError> {
    less_than_zero::<D, _, _>(&(b - a), fabric)
}

/// Implements the comparator a >= b
///
/// D represents the bitlength of a and b
pub fn greater_than_equal<const D: usize, N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    a: &AuthenticatedScalar<N, S>,
    b: &AuthenticatedScalar<N, S>,
    fabric: SharedFabric<N, S>,
) -> Result<AuthenticatedScalar<N, S>, MpcError> {
    Ok(Scalar::one() - less_than::<D, _, _>(a, b, fabric)?)
}
