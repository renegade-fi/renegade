//! Groups logic for computing modulo and truncation operators

use curve25519_dalek::scalar::Scalar;
use mpc_ristretto::{
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource,
    mpc_scalar::scalar_to_u64, network::MpcNetwork,
};

use crate::{
    errors::MpcError,
    mpc::SharedFabric,
    mpc_gadgets::bits::{bit_lt, scalar_to_bits_le},
};

use super::bits::scalar_from_bits_le;

/// Computes the value of the input modulo 2^m
pub fn mod_2m<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    a: &AuthenticatedScalar<N, S>,
    m: usize,
    fabric: SharedFabric<N, S>,
) -> Result<AuthenticatedScalar<N, S>, MpcError> {
    // Generate random blinding bits
    let random_bits = fabric
        .borrow_fabric()
        .allocate_random_shared_bit_batch(m /* num_zeros */);

    let random_lower_bits = scalar_from_bits_le(&random_bits);

    // Generate a random upper half to the scalar
    let mut random_upper_bits = fabric.borrow_fabric().allocate_random_shared_scalar();
    random_upper_bits *= Scalar::from(1u64 << m);

    // TODO: Fix this offset
    let blinding_factor = &random_upper_bits + &random_lower_bits;
    let blinded_value = a + &blinding_factor;

    let blinded_value_open = blinded_value.open_and_authenticate().map_err(|_| {
        MpcError::OpeningError("error opening blinded value while taking mod_2m".to_string())
    })?;
    let mod_opened_value = scalar_to_u64(&blinded_value_open.to_scalar()) % (1 << m);

    let mod_opened_value_bits = scalar_to_bits_le(Scalar::from(mod_opened_value))
        .into_iter()
        .map(|bit| fabric.borrow_fabric().allocate_public_scalar(bit))
        .take(m)
        .collect::<Vec<_>>();

    // If the modulus is negative, shift up by 2^m
    let shift_bit = Scalar::from(1u64 << m) * bit_lt(&mod_opened_value_bits, &random_bits, fabric);
    Ok(shift_bit + Scalar::from(mod_opened_value) - random_lower_bits)
}
