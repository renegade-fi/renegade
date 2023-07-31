//! Defines MPC gadgets for operating on fixed-point values

use circuit_types::fixed_point::{AuthenticatedFixedPoint, DEFAULT_FP_PRECISION};
use mpc_stark::{algebra::authenticated_scalar::AuthenticatedScalarResult, MpcFabric};

use super::modulo::shift_right;

/// Implements gadgets on top of the existing shared fixed point type
pub struct FixedPointMpcGadget;
impl FixedPointMpcGadget {
    /// Shift the given fixed point value to the right by the given number of bits
    /// and return the result as an integer
    pub fn as_integer(
        val: AuthenticatedFixedPoint,
        fabric: MpcFabric,
    ) -> AuthenticatedScalarResult {
        shift_right::<DEFAULT_FP_PRECISION>(&val.repr, fabric)
    }
}
