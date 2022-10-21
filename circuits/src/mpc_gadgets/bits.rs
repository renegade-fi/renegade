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
pub(crate) fn scalar_from_bits_le<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
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
pub(crate) fn scalar_to_bits_le(a: Scalar) -> Vec<Scalar> {
    // The byte (8 bit) boundary we must iterate through to fetch `M` bits
    BitSlice::<_, Lsb0>::from_slice(a.as_bytes())
        .iter()
        .by_vals()
        .map(|bit| if bit { Scalar::one() } else { Scalar::zero() })
        .collect::<Vec<Scalar>>()
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
pub fn bit_add<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    a: &[AuthenticatedScalar<N, S>],
    b: &[AuthenticatedScalar<N, S>],
    fabric: SharedFabric<N, S>,
) -> (Vec<AuthenticatedScalar<N, S>>, AuthenticatedScalar<N, S>) {
    bit_add_impl(a, b, fabric.borrow_fabric().allocate_zero())
}

/// Implementation of bit_add that exposes an extra inital_carry parameter
/// for circuit chaining
fn bit_add_impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    a: &[AuthenticatedScalar<N, S>],
    b: &[AuthenticatedScalar<N, S>],
    initial_carry: AuthenticatedScalar<N, S>,
) -> (Vec<AuthenticatedScalar<N, S>>, AuthenticatedScalar<N, S>) {
    assert_eq!(
        a.len(),
        b.len(),
        "bit_add takes bit representations of equal length"
    );
    let mut result = Vec::with_capacity(a.len());
    let mut carry = initial_carry;

    for (a_bit, b_bit) in a.iter().zip(b.iter()) {
        // The out bit in this position is A \xor B \xor carry
        let a_xor_b = bit_xor(a_bit, b_bit);
        result.push(bit_xor(&a_xor_b, &carry));
        // The carry bit from this depth of the adder
        carry = a_bit * b_bit + a_xor_b * &carry;
    }

    (result, carry)
}

/// CarryOut computes the carry after adding two bitstrings together
///
/// An initial carry bit may be supplied for use in chaining this circuit
pub fn carry_out<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    a: &[AuthenticatedScalar<N, S>],
    b: &[AuthenticatedScalar<N, S>],
    initial_carry: AuthenticatedScalar<N, S>,
) -> AuthenticatedScalar<N, S> {
    bit_add_impl(a, b, initial_carry).1
}

/// Decomposes the input into its `m` least significant bits
///
/// Here, we use the pre-processing functionality to blind and open a value
/// that can then be used to compute bitwise decompmositions of the input
pub fn to_bits_le<const D: usize, N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    x: &AuthenticatedScalar<N, S>,
    fabric: SharedFabric<N, S>,
) -> Result<Vec<AuthenticatedScalar<N, S>>, MpcError> {
    // If x is public, compute the bits locally
    if x.is_public() {
        return Ok(scalar_to_bits_le(x.to_scalar())
            .iter()
            .map(|bit| fabric.borrow_fabric().allocate_public_scalar(*bit))
            .collect::<Vec<_>>());
    }

    // Sample a random batch of bits and create a random m-bit shared scalar
    let random_bits = fabric
        .borrow_fabric()
        .allocate_random_shared_bit_batch(D /* num_scalars */);

    let random_scalar = scalar_from_bits_le(&random_bits);

    // Pop a random scalar to fill in the top k - m bits
    let mut random_upper_bits = fabric.borrow_fabric().allocate_random_shared_scalar();
    random_upper_bits *= Scalar::from(1u128 << D);

    // This value is used to blind the opening so that the opened value is distributed uniformly at
    // random over the scalar field
    let blinding_factor = random_upper_bits + random_scalar;
    // TODO: Do we need to `open_and_authenticate`?
    // TODO: Fix this offset
    let blinded_value = Scalar::from(1u128 << (D + 2)) + x - &blinding_factor;
    let blinded_value_open = blinded_value.open_and_authenticate().map_err(|_| {
        MpcError::OpeningError("error opening blinded value while truncating".to_string())
    })?;

    let blinded_value_bits = {
        let borrowed_fabric = fabric.borrow_fabric();
        scalar_to_bits_le(blinded_value_open.to_scalar())
            .into_iter()
            .map(|bit| borrowed_fabric.allocate_public_scalar(bit))
            .collect::<Vec<_>>()
    }; // borrowed_fabric dropped

    let (bits, _) = bit_add(
        blinded_value_bits[..D].try_into().unwrap(),
        random_bits[..D].try_into().unwrap(),
        fabric,
    );

    Ok(bits)
}

/// Given two bitwise representations, computes whether the first is less than the second
pub fn bit_lt<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    a: &[AuthenticatedScalar<N, S>],
    b: &[AuthenticatedScalar<N, S>],
    fabric: SharedFabric<N, S>,
) -> AuthenticatedScalar<N, S> {
    assert_eq!(
        a.len(),
        b.len(),
        "bit_lt_public_a takes equal length bit arrays"
    );

    // Invert `b`, add and then evaluate the carry
    let b_inverted = b.iter().map(|bit| Scalar::one() - bit).collect::<Vec<_>>();
    let carry = carry_out(
        a,
        &b_inverted,
        fabric.borrow_fabric().allocate_public_u64(1 /* value */),
    );

    Scalar::one() - carry
}
