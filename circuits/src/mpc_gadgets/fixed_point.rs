//! Defines MPC gadgets for operating on fixed-point values

use std::marker::PhantomData;

use circuit_types::{
    errors::MpcError,
    fixed_point::{AuthenticatedFixedPoint, DEFAULT_FP_PRECISION},
    SharedFabric,
};
use curve25519_dalek::scalar::Scalar;
use mpc_ristretto::{
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource, network::MpcNetwork,
};

use super::modulo::shift_right;

/// Implements gadgets on top of the existing shared fixed point type
pub struct FixedPointMpcGadget<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    PhantomData<(N, S)>,
);
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> FixedPointMpcGadget<N, S> {
    /// Shift the given fixed point value to the right by the given number of bits
    /// and return the result as an integer
    pub fn as_integer(
        val: AuthenticatedFixedPoint<N, S>,
        fabric: SharedFabric<N, S>,
    ) -> Result<AuthenticatedScalar<N, S>, MpcError> {
        shift_right::<DEFAULT_FP_PRECISION, N, S>(&val.repr, fabric)
    }
}
