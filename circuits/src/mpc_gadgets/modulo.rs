//! Groups logic for computing modulo and truncation operators

use mpc_stark::{
    algebra::{
        authenticated_scalar::AuthenticatedScalarResult,
        scalar::{Scalar, ScalarResult},
    },
    MpcFabric, ResultValue,
};
use num_bigint::BigUint;

use crate::{scalar_2_to_m, SCALAR_MAX_BITS};

use super::bits::{bit_lt_public, scalar_from_bits_le, scalar_to_bits_le};

// -----------
// | Helpers |
// -----------

/// Take a `ScalarResult` modulo a power of 2
fn scalar_mod_2m(val: &ScalarResult, m: usize) -> ScalarResult {
    val.fabric().new_gate_op(vec![val.id()], move |args| {
        let val: Scalar = args[0].clone().into();
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
/// Blinds the value with a random scalar, opens the blinded value, applies the modulo
/// operator, then inverts the blinding.
///
/// One catch is that if the resulting value of the modulo is less than the blinding
/// factor, we have to shift the value up by one addition of the modulus.
pub fn mod_2m<const M: usize>(
    a: &AuthenticatedScalarResult,
    fabric: MpcFabric,
) -> AuthenticatedScalarResult {
    // The input has 256 bits, so any modulus larger can be ignored
    if M >= 256 {
        return a.clone();
    }
    let scalar_2m = scalar_2_to_m(M);

    // Generate random blinding bits
    let random_bits = fabric.random_shared_bits(M);

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
    let value_open_mod_2m = scalar_mod_2m(&blinded_value_open.value, M);

    // Decompose into bits
    let mod_opened_value_bits = scalar_to_bits_le::<M>(&value_open_mod_2m);

    // If the modulus is negative, shift up by 2^m
    let shift_bit = scalar_2m * bit_lt_public(&random_bits, &mod_opened_value_bits, fabric);

    shift_bit + value_open_mod_2m - random_lower_bits
}

/// Computes the input with the `m` least significant bits truncated
pub fn truncate<const M: usize>(
    x: &AuthenticatedScalarResult,
    fabric: MpcFabric,
) -> AuthenticatedScalarResult {
    // Apply mod2m and then subtract the result to make the value divisible by a public 2^-m
    if M >= SCALAR_MAX_BITS {
        return fabric.zero_authenticated();
    }

    let x_mod_2m = mod_2m::<M>(x, fabric);
    let res = scalar_2_to_m(M).inverse() * (x - &x_mod_2m);

    res
}

/// Shifts the input right by the specified amount
///
/// Effectively just calls out to truncate, but is placed here for abstraction purposes
pub fn shift_right<const M: usize>(
    a: &AuthenticatedScalarResult,
    fabric: MpcFabric,
) -> AuthenticatedScalarResult {
    if M >= 256 {
        return fabric.zero_authenticated();
    }

    truncate::<M>(a, fabric)
}
