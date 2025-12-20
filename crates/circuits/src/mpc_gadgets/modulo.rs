//! Groups logic for computing modulo and truncation operators

use ark_mpc::ResultValue;
use circuit_types::Fabric;
use constants::{AuthenticatedScalar, Scalar, ScalarResult};
use num_bigint::BigUint;

use crate::{SCALAR_MAX_BITS, scalar_2_to_m};

use super::bits::{bit_lt_public, scalar_from_bits_le, scalar_to_bits_le};

// -----------
// | Helpers |
// -----------

/// Take a `ScalarResult` modulo a power of 2
fn scalar_mod_2m(val: &ScalarResult, m: usize) -> ScalarResult {
    val.fabric().new_gate_op(vec![val.id()], move |mut args| {
        let val: Scalar = args.next().unwrap().into();
        let val_biguint = val.to_biguint();

        let res = val_biguint % &(BigUint::from(1u8) << m);
        ResultValue::Scalar(res.into())
    })
}

// -----------
// | Gadgets |
// -----------

/// Computes the value of the input modulo 2^m
///
/// Blinds the value with a random scalar, opens the blinded value, applies the
/// modulo operator, then inverts the blinding.
///
/// One catch is that if the resulting value of the modulo is less than the
/// blinding factor, we have to shift the value up by one addition of the
/// modulus.
///
/// TODO: Define a signed integer maximum for this and other MPC gadgets as per:
///     https://faui1-files.cs.fau.de/filepool/publications/octavian_securescm/smcint-scn10.pdf
pub fn mod_2m(a: &AuthenticatedScalar, m: usize, fabric: &Fabric) -> AuthenticatedScalar {
    // The input has 256 bits, so any modulus larger can be ignored
    if m >= 256 {
        return a.clone();
    }
    let scalar_2m = scalar_2_to_m(m as u64);

    // Generate random blinding bits
    let random_bits = fabric.random_shared_bits(m);

    let random_lower_bits = if random_bits.is_empty() {
        fabric.zero_authenticated()
    } else {
        scalar_from_bits_le(&random_bits)
    };

    // Generate a random upper half to the scalar
    let random_upper_bits = scalar_2m * &fabric.random_shared_scalars(1 /* num_scalars */)[0];
    let blinding_factor = random_upper_bits + &random_lower_bits;

    let blinded_value = a + &blinding_factor;
    let blinded_value_open = blinded_value.open_authenticated();

    // Take the blinded, opened value mod 2^m
    let value_open_mod_2m = scalar_mod_2m(&blinded_value_open.value, m);

    // Decompose into bits
    let mod_opened_value_bits = scalar_to_bits_le(&value_open_mod_2m, m);

    // If the modulus is negative, shift up by 2^m
    let bit_lt = bit_lt_public(&mod_opened_value_bits, &random_bits, fabric);

    let shift_bit = scalar_2m * bit_lt;
    shift_bit + value_open_mod_2m - random_lower_bits
}

/// Computes the input with the `m` least significant bits truncated
pub fn truncate(x: &AuthenticatedScalar, m: usize, fabric: &Fabric) -> AuthenticatedScalar {
    // Apply mod2m and then subtract the result to make the value divisible by a
    // public 2^-m
    if m >= SCALAR_MAX_BITS {
        return fabric.zero_authenticated();
    }

    let x_mod_2m = mod_2m(x, m, fabric);
    scalar_2_to_m(m as u64).inverse() * (x - &x_mod_2m)
}

/// Shifts the input right by the specified amount
///
/// Effectively just calls out to truncate, but is placed here for abstraction
/// purposes
pub fn shift_right(a: &AuthenticatedScalar, m: usize, fabric: &Fabric) -> AuthenticatedScalar {
    if m >= 256 {
        return fabric.zero_authenticated();
    }

    truncate(a, m, fabric)
}

#[cfg(test)]
mod tests {
    use ark_mpc::PARTY0;
    use circuit_types::errors::MpcError;
    use constants::Scalar;
    use num_bigint::BigUint;
    use rand::{Rng, RngCore, thread_rng};
    use test_helpers::mpc_network::execute_mock_mpc;

    use crate::mpc_gadgets::modulo::{mod_2m, shift_right};

    /// Test the `mod2m` gadget
    #[tokio::test]
    async fn test_mod2m() {
        let mut rng = thread_rng();
        const M: usize = 32;
        let value = Scalar::from(rng.r#gen::<u128>());

        let (res, _): (Result<bool, MpcError>, _) = execute_mock_mpc(move |fabric| async move {
            let shared_value = fabric.share_scalar(value, PARTY0);
            let res = mod_2m(&shared_value, M, &fabric).open_authenticated().await.unwrap();

            let expected = Scalar::from(value.to_biguint() % (BigUint::from(1u8) << M));
            Ok(res == expected)
        })
        .await;

        let res = res.unwrap();
        assert!(res)
    }

    /// Test the shift right gadget
    #[tokio::test]
    async fn test_shift_right() {
        const SHIFT_AMOUNT: usize = 3;
        let value = thread_rng().next_u32();

        let (res, _): (Result<bool, MpcError>, _) = execute_mock_mpc(move |fabric| async move {
            let shared_value = fabric.share_scalar(value, PARTY0);
            let res = shift_right(&shared_value, SHIFT_AMOUNT, &fabric)
                .open_authenticated()
                .await
                .unwrap();

            Ok(res == Scalar::from(value >> SHIFT_AMOUNT))
        })
        .await;

        assert!(res.unwrap())
    }
}
