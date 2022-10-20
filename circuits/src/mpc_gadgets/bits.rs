//! Groups logic around translating between Scalars and bits

use bitvec::order::Lsb0;
use bitvec::slice::BitSlice;
use curve25519_dalek::scalar::Scalar;
use mpc_ristretto::{
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource, network::MpcNetwork,
};

use crate::{errors::MpcError, mpc::SharedFabric};

/**
 * Helpers
 */
/// Composes a sequence of `Scalar`s representing bits in little endian order into a single scalar
fn scalar_from_bits_le<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    bits: &[AuthenticatedScalar<N, S>],
) -> AuthenticatedScalar<N, S> {
    assert!(
        !bits.is_empty(),
        "scalar_from_bits_le cannot be called with empty bit array"
    );
    let two = Scalar::from(2u64);
    let mut result = bits[bits.len() - 1].clone();

    for bit in bits.iter().rev().skip(1) {
        result = &result * two + bit;
    }

    result
}

/// Returns a list of `Scalar`s representing the `m` least signficant bits of `a`
fn scalar_to_bits_le<const M: usize>(a: Scalar) -> [Scalar; M] {
    // The byte (8 bit) boundary we must iterate through to fetch `M` bits
    BitSlice::<_, Lsb0>::from_slice(a.as_bytes())
        .iter()
        .by_vals()
        .map(|bit| if bit { Scalar::one() } else { Scalar::zero() })
        .collect::<Vec<Scalar>>()[..M]
        .try_into()
        .unwrap()
}

/**
 * Gadgets
 */
/// Single bit xor, assumes that `a` and `b` are scalars representing bits
pub fn bit_xor<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    a: &AuthenticatedScalar<N, S>,
    b: &AuthenticatedScalar<N, S>,
) -> AuthenticatedScalar<N, S> {
    // xor(a, b) = a + b - 2ab
    a + b - Scalar::from(2u64) * a * b
}

/// Bitwise Add with carry; inputs assumed to be in little endian order
///
/// Returns the added bits and a bit indicating whether the value has overflowed
pub fn bit_add<const D: usize, N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    a: &[AuthenticatedScalar<N, S>; D],
    b: &[AuthenticatedScalar<N, S>; D],
    fabric: SharedFabric<N, S>,
) -> (Vec<AuthenticatedScalar<N, S>>, AuthenticatedScalar<N, S>) {
    let mut result = Vec::with_capacity(D);
    let mut carry = fabric.borrow_fabric().allocate_zero();

    for (a_bit, b_bit) in a.iter().zip(b.iter()) {
        // The out bit in this position is A \xor B \xor carry
        let a_xor_b = bit_xor(a_bit, b_bit);
        result.push(bit_xor(&a_xor_b, &carry));
        // The carry bit from this depth of the adder
        carry = a_bit * b_bit + a_xor_b * &carry;
    }

    (result, carry)
}

/// Decomposes the input into its `m` least significant bits
///
/// Here, we use the pre-processing functionality to blind and open a value
/// that can then be used to compute bitwise decompmositions of the input
pub fn to_bits_le<const D: usize, N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    x: AuthenticatedScalar<N, S>,
    fabric: SharedFabric<N, S>,
) -> Result<Vec<AuthenticatedScalar<N, S>>, MpcError> {
    // Sample a random batch of bits and create a random m-bit shared scalar
    let random_bits = fabric
        .borrow_fabric()
        .allocate_random_shared_bit_batch(D /* num_scalars */);

    let random_scalar = scalar_from_bits_le(&random_bits);

    // Pop a random scalar to fill in the top k - m bits
    let mut random_upper_bits = fabric.borrow_fabric().allocate_random_shared_scalar();
    random_upper_bits *= Scalar::from(2u64 << D);

    // This value is used to blind the opening so that the opened value is distributed uniformly at
    // random over the scalar field
    let blinding_factor = random_upper_bits + random_scalar;
    // TODO: Do we need to `open_and_authenticate`?
    // TODO: Fix this offset
    let blinded_value = Scalar::from((2u64 << (2 * D)) as u64) + &x - &blinding_factor;
    let blinded_value_open = blinded_value.open_and_authenticate().map_err(|_| {
        MpcError::OpeningError("error opening blinded value while truncating".to_string())
    })?;

    let blinded_value_bits = {
        let borrowed_fabric = fabric.borrow_fabric();
        scalar_to_bits_le::<D>(blinded_value_open.to_scalar())
            .into_iter()
            .map(|bit| borrowed_fabric.allocate_public_scalar(bit))
            .collect::<Vec<_>>()
    }; // borrowed_fabric dropped

    let (bits, _) = bit_add::<D, N, S>(
        blinded_value_bits[..D].try_into().unwrap(),
        random_bits[..D].try_into().unwrap(),
        fabric,
    );

    Ok(bits)
}
