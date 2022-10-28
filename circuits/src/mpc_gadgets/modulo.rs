//! Groups logic for computing modulo and truncation operators

use curve25519_dalek::scalar::Scalar;
use mpc_ristretto::{
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource, network::MpcNetwork,
};
use num_bigint::BigInt;

use crate::{
    bigint_to_scalar, bigint_to_scalar_bits, errors::MpcError, mpc::SharedFabric,
    mpc_gadgets::bits::bit_lt, scalar_2_to_m, scalar_to_bigint, SCALAR_MAX_BITS,
};

use super::bits::scalar_from_bits_le;

/// Computes the value of the input modulo 2^m
pub fn mod_2m<const M: usize, N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    a: &AuthenticatedScalar<N, S>,
    fabric: SharedFabric<N, S>,
) -> Result<AuthenticatedScalar<N, S>, MpcError> {
    // The input has 256 bits, so any modulus larger can be ignored
    if M >= 256 {
        return Ok(a.clone());
    }
    let scalar_2m = scalar_2_to_m(M);

    // Generate random blinding bits
    let random_bits = fabric
        .borrow_fabric()
        .allocate_random_shared_bit_batch(M /* num_zeros */);

    let random_lower_bits = if random_bits.is_empty() {
        fabric.borrow_fabric().allocate_zero()
    } else {
        scalar_from_bits_le(&random_bits)
    };

    // Generate a random upper half to the scalar
    // If m is between 128 and 256, we split up the shift into two separate multiplications
    // let mut random_upper_bits = fabric.borrow_fabric().allocate_random_shared_scalar();
    // random_upper_bits *= scalar_2m;
    let random_upper_bits = fabric.borrow_fabric().allocate_zero();

    let blinding_factor = &random_upper_bits + &random_lower_bits;

    let blinded_value = a + &blinding_factor;
    let blinded_value_open = blinded_value.open_and_authenticate().map_err(|_| {
        MpcError::OpeningError("error opening blinded value while taking mod_2m".to_string())
    })?;

    // Convert to bigint for fast mod
    let value_open_mod_2m =
        scalar_to_bigint(&blinded_value_open.to_scalar()) % (BigInt::from(1) << M);

    let mod_opened_value_bits = bigint_to_scalar_bits::<M>(&value_open_mod_2m)
        .into_iter()
        .map(|bit| fabric.borrow_fabric().allocate_public_scalar(bit))
        .take(M)
        .collect::<Vec<_>>();

    // If the modulus is negative, shift up by 2^m
    let shift_bit = scalar_2m * bit_lt(&mod_opened_value_bits, &random_bits, fabric);

    Ok(shift_bit + bigint_to_scalar(&value_open_mod_2m) - random_lower_bits)
}

/// Computes the input with the `m` least significant bits truncated
pub fn truncate<const M: usize, N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    x: &AuthenticatedScalar<N, S>,
    fabric: SharedFabric<N, S>,
) -> Result<AuthenticatedScalar<N, S>, MpcError> {
    // Apply mod2m and then subtract the result to make the value divisible by a public 2^-m
    if M >= SCALAR_MAX_BITS {
        return Ok(fabric.borrow_fabric().allocate_zero());
    }

    let x_mod_2m = mod_2m::<M, _, _>(x, fabric)?;
    let res = scalar_2_to_m(M).invert() * (x - &x_mod_2m);

    Ok(res)
}

/// Shifts the input right by the specified amount
///
/// Effectively just calls out to truncate, but is placed here for abstraction purposes
pub fn shift_right<const M: usize, N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    a: &AuthenticatedScalar<N, S>,
    fabric: SharedFabric<N, S>,
) -> Result<AuthenticatedScalar<N, S>, MpcError> {
    if M >= 256 {
        return Ok(fabric.borrow_fabric().allocate_zero());
    }

    truncate::<M, _, _>(a, fabric)
}
