//! Groups logic around translating between Scalars and bits

use std::cmp;

use bitvec::{order::Lsb0, slice::BitSlice};
use curve25519_dalek::scalar::Scalar;

use mpc_ristretto::{
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource, network::MpcNetwork,
};

use crate::{errors::MpcError, mpc::SharedFabric, scalar_2_to_m, SCALAR_MAX_BITS};

/// We only sample a blinding factor in the range [0, 2^252] because not all values
/// with the final bit (253rd) of the value make valid scalars. The scalar field is
/// of size 2^252 + \delta
const BLINDING_FACTOR_MAX_BITS: usize = 252;

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
pub(crate) fn scalar_to_bits_le(a: &Scalar) -> Vec<Scalar> {
    // The byte (8 bit) boundary we must iterate through to fetch `M` bits
    let bits = BitSlice::<_, Lsb0>::from_slice(a.as_bytes())
        .iter()
        .by_vals()
        .map(|bit| if bit { Scalar::one() } else { Scalar::zero() })
        .collect::<Vec<Scalar>>();

    bits
}

/// Converts the input bitvector to be exactly of the given length
///
/// If the bitvector is shorter than the desired length, it is padded with
/// zeros. If the bitvectors is longer than the desired length, it is truncated
pub(crate) fn resize_bitvector_to_length<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    mut bitvec: Vec<AuthenticatedScalar<N, S>>,
    desired_length: usize,
    fabric: SharedFabric<N, S>,
) -> Vec<AuthenticatedScalar<N, S>> {
    // Push allocated zeros to the end of the array
    if bitvec.len() < desired_length {
        bitvec.append(
            &mut fabric
                .borrow_fabric()
                .allocate_zeros(desired_length - bitvec.len()),
        )
    }

    // Truncate in the case that the desired length results in a shrinking
    bitvec[..desired_length].to_vec()
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
    bit_add_impl(
        a,
        b,
        fabric.borrow_fabric().allocate_zero(), /* initial_carry */
    )
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
    assert!(
        D < SCALAR_MAX_BITS,
        "Can only support scalars of up to {:?} bits",
        SCALAR_MAX_BITS
    );
    // If x is public, compute the bits locally
    if x.is_public() {
        return Ok(scalar_to_bits_le(&x.to_scalar())
            .iter()
            .map(|bit| fabric.borrow_fabric().allocate_public_scalar(*bit))
            .collect::<Vec<_>>());
    }

    // Sample a random batch of bits and create a random m-bit shared scalar
    let random_bits =
        fabric
            .borrow_fabric()
            .allocate_random_shared_bit_batch(
                cmp::min(D, BLINDING_FACTOR_MAX_BITS), /* num_scalars */
            );
    let random_scalar = scalar_from_bits_le(&random_bits);

    // Pop a random scalar to fill in the top k - m bits
    let random_upper_bits = if D < SCALAR_MAX_BITS {
        fabric.borrow_fabric().allocate_random_shared_scalar() * scalar_2_to_m(D)
    } else {
        fabric.borrow_fabric().allocate_zero()
    };

    // This value is used to blind the opening so that the opened value is distributed uniformly at
    // random over the scalar field
    let blinding_factor = &random_upper_bits + &random_scalar;

    // TODO: Do we need to `open_and_authenticate`?
    // TODO: Fix this offset
    let blinded_value = x - &blinding_factor + scalar_2_to_m(D + 1);
    let blinded_value_open = blinded_value.open().map_err(|_| {
        MpcError::OpeningError("error opening blinded value while truncating".to_string())
    })?;

    // Convert to bits
    let blinded_value_bits = fabric
        .borrow_fabric()
        .batch_allocate_public_scalar(&scalar_to_bits_le(&blinded_value_open.to_scalar()));
    let (bits, _) = bit_add(
        &resize_bitvector_to_length(blinded_value_bits, D, fabric.clone()),
        &resize_bitvector_to_length(random_bits, D, fabric.clone()),
        fabric,
    );

    Ok(bits)
}

/// Given two bitwise representations, computes whether the first is less than the second
///
/// Intuitively, we consider that a and b are in two's comlement representation. We flip all
/// the bits of `b`; which gives us a representation of -b - 1. In two's complement, the negation
/// of a value represents the distance of that value to the group order. If b > a; the distance
/// from b to the group order is smaller than that of a to the group order. Adding `b`'s "distance"
/// to `a` will then not cause an overflow (carry bit is 0). If b < a; the distance from `b` to the
/// group order is greater than that of `a` to the group order; so adding `b`'s distance to `a`
/// will cause an overflow.
///
/// Using -b - 1 instead of -b is the difference between the < and <= operators
pub fn bit_lt<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    a: &[AuthenticatedScalar<N, S>],
    b: &[AuthenticatedScalar<N, S>],
    fabric: SharedFabric<N, S>,
) -> AuthenticatedScalar<N, S> {
    assert_eq!(a.len(), b.len(), "bit_lt takes equal length bit arrays");
    // Invert `b`, add and then evaluate the carry
    let b_inverted = b.iter().map(|bit| Scalar::one() - bit).collect::<Vec<_>>();
    let carry = carry_out(
        a,
        &b_inverted,
        fabric.borrow_fabric().allocate_public_u64(1 /* value */),
    );

    Scalar::one() - carry
}

#[cfg(test)]
mod tests {
    use std::iter;

    use crypto::fields::{bigint_to_scalar, scalar_to_bigint};
    use curve25519_dalek::scalar::Scalar;
    use integration_helpers::mpc_network::mock_mpc_fabric;
    use mpc_ristretto::mpc_scalar::scalar_to_u64;
    use num_bigint::BigInt;
    use rand::{thread_rng, Rng, RngCore};

    use super::{scalar_from_bits_le, scalar_to_bits_le};

    #[test]
    fn test_scalar_to_bits() {
        let random_u64 = thread_rng().next_u64();
        let scalar = Scalar::from(random_u64);
        let bits = scalar_to_bits_le(&scalar);

        let reconstructed = bits
            .iter()
            .rev()
            .fold(Scalar::zero(), |acc, bit| acc * Scalar::from(2u64) + bit);

        assert_eq!(scalar, reconstructed);
    }

    #[test]
    fn test_scalar_to_bits_all_one() {
        let n = 250; // Power of 2 to fills bits up to
        let scalar_bits = 256; // The number of bits used to store a scalar
        let scalar = (0..n).fold(Scalar::zero(), |acc, _| {
            acc * Scalar::from(2u64) + Scalar::from(1u64)
        });

        let res = scalar_to_bits_le(&scalar)
            .iter()
            .map(scalar_to_u64)
            .collect::<Vec<_>>();
        let expected_bits = (0..n)
            .map(|_| 1u64)
            .chain(iter::repeat(0u64).take(scalar_bits - n))
            .collect::<Vec<_>>();
        assert_eq!(res, expected_bits);
    }

    #[test]
    fn test_scalar_from_bits() {
        let mock_fabric = mock_mpc_fabric(0 /* party_id */);
        let mut rng = thread_rng();
        let random_bits = (0..252)
            .map(|_| rng.gen_bool(0.5 /* p */) as u64)
            .collect::<Vec<_>>();

        let random_scalar_bits = mock_fabric
            .as_ref()
            .borrow()
            .batch_allocate_public_u64s(&random_bits);
        let res = scalar_from_bits_le(&random_scalar_bits);
        let res_bigint = scalar_to_bigint(&res.to_scalar());

        let expected_res = random_bits
            .into_iter()
            .rev()
            .map(BigInt::from)
            .fold(BigInt::from(0u64), |acc, val| acc * 2 + val);

        assert_eq!(res_bigint, expected_res);
    }

    #[test]
    fn test_scalar_from_bits_all_one() {
        let n = 250; // The number of bits to fill in as ones
        let scalar_bits = 256; // The number of bits used to store a Scalar
        let mock_fabric = mock_mpc_fabric(0 /* party_id */);

        let bits = (0..n)
            .map(|_| mock_fabric.as_ref().borrow().allocate_public_u64(1u64))
            .chain(
                iter::repeat(mock_fabric.as_ref().borrow().allocate_zero()).take(scalar_bits - n),
            )
            .collect::<Vec<_>>();

        let res = scalar_from_bits_le(&bits);
        let expected_res = (0..n).fold(BigInt::from(0u64), |acc, _| acc * 2 + 1);

        let res_bits = scalar_to_bits_le(&res.to_scalar());
        let num_ones = res_bits
            .iter()
            .cloned()
            .filter(|bit| bit.eq(&Scalar::one()))
            .count();

        assert_eq!(num_ones, n);
        assert_eq!(res.to_scalar(), bigint_to_scalar(&expected_res));
    }
}
