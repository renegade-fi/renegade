//! Defines MPC gadgets for operating on fixed-point values

use circuit_types::{
    Fabric,
    fixed_point::{AuthenticatedFixedPoint, DEFAULT_FP_PRECISION},
};
use constants::AuthenticatedScalar;

use super::modulo::shift_right;

/// Implements gadgets on top of the existing shared fixed point type
pub struct FixedPointMpcGadget;
impl FixedPointMpcGadget {
    /// Shift the given fixed point value to the right by the given number of
    /// bits and return the result as an integer
    pub fn as_integer(val: &AuthenticatedFixedPoint, fabric: &Fabric) -> AuthenticatedScalar {
        shift_right(&val.repr, DEFAULT_FP_PRECISION, fabric)
    }
}

#[cfg(test)]
mod test {
    use ark_mpc::PARTY0;
    use circuit_types::{fixed_point::FixedPoint, traits::MpcBaseType};
    use rand::{Rng, RngCore, thread_rng};
    use test_helpers::mpc_network::execute_mock_mpc;

    use crate::{mpc_gadgets::fixed_point::FixedPointMpcGadget, open_unwrap};

    /// Tests the `as_integer` gadget
    #[tokio::test]
    async fn test_as_integer() {
        let mut rng = thread_rng();

        // Test `floor` on both an integral and fractional value
        let fp = rng.gen_range(0.0..100.);
        let int = rng.next_u64();

        let fixed1 = FixedPoint::from_f64_round_down(fp);
        let fixed2 = FixedPoint::from_integer(int);

        let expected1 = fixed1.floor();
        let expected2 = fixed2.floor();

        let ((res1, res2), _) = execute_mock_mpc(move |fabric| async move {
            let fp1_shared = fixed1.allocate(PARTY0, &fabric);
            let fp2_shared = fixed2.allocate(PARTY0, &fabric);

            let res1 = FixedPointMpcGadget::as_integer(&fp1_shared, &fabric);
            let res2 = FixedPointMpcGadget::as_integer(&fp2_shared, &fabric);

            (open_unwrap!(res1), open_unwrap!(res2))
        })
        .await;

        assert_eq!(res1, expected1);
        assert_eq!(res2, expected2);
    }
}
