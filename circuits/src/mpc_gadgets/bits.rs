//! Groups logic around translating between Scalars and bits

use std::{cmp, iter};

use bitvec::{prelude::Lsb0, slice::BitSlice};
use itertools::Itertools;
use mpc_stark::{
    algebra::{
        authenticated_scalar::AuthenticatedScalarResult,
        scalar::{Scalar, ScalarResult},
    },
    MpcFabric, ResultValue,
};

use crate::{scalar_2_to_m, SCALAR_MAX_BITS};

/// We only sample a blinding factor in the range [0, 2^252] because not all values
/// with the final bit (253rd) of the value make valid scalars. The scalar field is
/// of size 2^252 + \delta
const BLINDING_FACTOR_MAX_BITS: usize = 252;

// -----------
// | Helpers |
// -----------

/// Composes a sequence of `Scalar`s representing bits in little endian order into a single scalar
pub(crate) fn scalar_from_bits_le(bits: &[AuthenticatedScalarResult]) -> AuthenticatedScalarResult {
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

/// Returns a list of `Scalar`s representing the `m` least significant bits of `a`
pub(crate) fn scalar_to_bits_le<const N: usize>(a: &ScalarResult) -> Vec<ScalarResult> {
    // The byte (8 bit) boundary we must iterate through to fetch `M` bits
    a.fabric().new_batch_gate_op(vec![a.id()], N, |mut args| {
        let a: Scalar = args.pop().unwrap().into();
        let a_bigint = a.to_biguint();

        BitSlice::<_, Lsb0>::from_slice(&a_bigint.to_bytes_le())
            .iter()
            .by_vals()
            .map(|bit| if bit { Scalar::one() } else { Scalar::zero() })
            .chain(iter::repeat(Scalar::zero()))
            .take(N)
            .map(ResultValue::Scalar)
            .collect_vec()
    })
}

/// Converts the input bitvector to be exactly of the given length
///
/// If the bitvector is shorter than the desired length, it is padded with
/// zeros. If the bitvectors is longer than the desired length, it is truncated
pub(crate) fn resize_bitvector_to_length(
    mut bitvec: Vec<AuthenticatedScalarResult>,
    desired_length: usize,
    fabric: &MpcFabric,
) -> Vec<AuthenticatedScalarResult> {
    // Push allocated zeros to the end of the array
    if bitvec.len() < desired_length {
        bitvec.append(&mut fabric.zeros_authenticated(desired_length - bitvec.len()))
    }

    // Truncate in the case that the desired length results in a shrinking
    bitvec[..desired_length].to_vec()
}

/// Converts the input bitvector to be exactly of the given length for a public input
///
/// If the bitvector is shorter than the desired length, it is padded with
/// zeros. If the bitvectors is longer than the desired length, it is truncated
pub(crate) fn resize_bitvector_to_length_public(
    mut bitvec: Vec<ScalarResult>,
    desired_length: usize,
    fabric: &MpcFabric,
) -> Vec<ScalarResult> {
    // Push allocated zeros to the end of the array
    let length_diff = desired_length - bitvec.len();
    if length_diff > 0 {
        bitvec.append(&mut (0..length_diff).map(|_| fabric.zero()).collect())
    }

    // Truncate in the case that the desired length results in a shrinking
    bitvec[..desired_length].to_vec()
}

// -----------
// | Gadgets |
// -----------

/// Single bit xor, assumes that `a` and `b` are scalars representing bits
pub fn bit_xor(
    a: &AuthenticatedScalarResult,
    b: &AuthenticatedScalarResult,
) -> AuthenticatedScalarResult {
    // xor(a, b) = a + b - 2ab
    a + b - Scalar::from(2u64) * a * b
}

/// Single bit xor where one of the bits is public
pub fn bit_xor_public(
    a: &ScalarResult,
    b: &AuthenticatedScalarResult,
) -> AuthenticatedScalarResult {
    // xor(a, b) = a + b - 2ab
    a + b - Scalar::from(2u64) * a * b
}

/// Bitwise Add with carry; inputs assumed to be in little endian order
///
/// Returns the added bits and a bit indicating whether the value has overflowed
pub fn bit_add(
    a: &[AuthenticatedScalarResult],
    b: &[AuthenticatedScalarResult],
    fabric: &MpcFabric,
) -> (Vec<AuthenticatedScalarResult>, AuthenticatedScalarResult) {
    bit_add_impl(a, b, fabric.zero_authenticated() /* initial_carry */)
}

/// Implementation of bit_add that exposes an extra inital_carry parameter
/// for circuit chaining
fn bit_add_impl(
    a: &[AuthenticatedScalarResult],
    b: &[AuthenticatedScalarResult],
    initial_carry: AuthenticatedScalarResult,
) -> (Vec<AuthenticatedScalarResult>, AuthenticatedScalarResult) {
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

/// Bitwise Add with carry; inputs assumed to be in little endian order
///
/// Returns the added bits and a bit indicating whether the value has overflowed
pub fn bit_add_public(
    a: &[ScalarResult],
    b: &[AuthenticatedScalarResult],
    fabric: &MpcFabric,
) -> (Vec<AuthenticatedScalarResult>, AuthenticatedScalarResult) {
    bit_add_impl_public(a, b, fabric.zero_authenticated() /* initial_carry */)
}

/// Implementation of `bit_add` that takes the second input as public values
fn bit_add_impl_public(
    a: &[ScalarResult],
    b: &[AuthenticatedScalarResult],
    initial_carry: AuthenticatedScalarResult,
) -> (Vec<AuthenticatedScalarResult>, AuthenticatedScalarResult) {
    assert_eq!(
        a.len(),
        b.len(),
        "bit_add takes bit representations of equal length"
    );
    let mut result = Vec::with_capacity(a.len());
    let mut carry = initial_carry;

    for (a_bit, b_bit) in a.iter().zip(b.iter()) {
        // The out bit in this position is A \xor B \xor carry
        let a_xor_b = bit_xor_public(a_bit, b_bit);
        result.push(bit_xor(&a_xor_b, &carry));
        // The carry bit from this depth of the adder
        carry = a_bit * b_bit + a_xor_b * &carry;
    }

    (result, carry)
}

/// CarryOut computes the carry after adding two bitstrings together
///
/// An initial carry bit may be supplied for use in chaining this circuit
pub fn carry_out(
    a: &[AuthenticatedScalarResult],
    b: &[AuthenticatedScalarResult],
    initial_carry: AuthenticatedScalarResult,
) -> AuthenticatedScalarResult {
    bit_add_impl(a, b, initial_carry).1
}

/// A `carry_out` implementation that takes the second input as public values
pub fn carry_out_public(
    a: &[ScalarResult],
    b: &[AuthenticatedScalarResult],
    initial_carry: AuthenticatedScalarResult,
) -> AuthenticatedScalarResult {
    bit_add_impl_public(a, b, initial_carry).1
}

/// Decomposes the input into its `m` least significant bits
///
/// Here, we use the pre-processing functionality to blind and open a value
/// that can then be used to compute bitwise decompositions of the input
pub fn to_bits_le<const D: usize>(
    x: &AuthenticatedScalarResult,
    fabric: &MpcFabric,
) -> Vec<AuthenticatedScalarResult> {
    assert!(
        D < SCALAR_MAX_BITS,
        "Can only support scalars of up to {:?} bits",
        SCALAR_MAX_BITS
    );

    // Sample a random batch of bits and create a random m-bit shared scalar
    let random_bits =
        fabric.random_shared_bits(cmp::min(D, BLINDING_FACTOR_MAX_BITS) /* num_scalars */);
    let random_scalar = scalar_from_bits_le(&random_bits);

    // Pop a random scalar to fill in the top k - m bits
    let random_upper_bits = if D < SCALAR_MAX_BITS {
        &fabric.random_shared_scalars(1 /* n */)[0] * scalar_2_to_m(D)
    } else {
        fabric.zero()
    };

    // This value is used to blind the opening so that the opened value is distributed uniformly at
    // random over the scalar field
    let blinding_factor = &random_upper_bits + &random_scalar;

    // TODO: Do we need to `open_and_authenticate`?
    let blinded_value = x - &blinding_factor + scalar_2_to_m(D + 1);
    let blinded_value_open = blinded_value.open();

    // Convert to bits
    let blinded_value_bits = scalar_to_bits_le::<D>(&blinded_value_open);
    let (bits, _) = bit_add_public(
        &resize_bitvector_to_length_public(blinded_value_bits, D, fabric),
        &resize_bitvector_to_length(random_bits, D, fabric),
        fabric,
    );

    bits
}

/// Given two bitwise representations, computes whether the first is less than the second
///
/// Intuitively, we consider that a and b are in two's complement representation. We flip all
/// the bits of `b`; which gives us a representation of -b - 1. In two's complement, the negation
/// of a value represents the distance of that value to the group order. If b > a; the distance
/// from b to the group order is smaller than that of a to the group order. Adding `b`'s "distance"
/// to `a` will then not cause an overflow (carry bit is 0). If b < a; the distance from `b` to the
/// group order is greater than that of `a` to the group order; so adding `b`'s distance to `a`
/// will cause an overflow.
///
/// Using -b - 1 instead of -b is the difference between the < and <= operators
pub fn bit_lt(
    a: &[AuthenticatedScalarResult],
    b: &[AuthenticatedScalarResult],
    fabric: &MpcFabric,
) -> AuthenticatedScalarResult {
    assert_eq!(a.len(), b.len(), "bit_lt takes equal length bit arrays");

    // Invert `b`, add and then evaluate the carry
    let b_inverted = b.iter().map(|bit| Scalar::one() - bit).collect_vec();
    let carry = carry_out(a, &b_inverted, fabric.one_authenticated());

    Scalar::one() - carry
}

/// A `bit_lt` implementation that takes one of the inputs as public
pub fn bit_lt_public(
    a: &[ScalarResult],
    b: &[AuthenticatedScalarResult],
    fabric: &MpcFabric,
) -> AuthenticatedScalarResult {
    assert_eq!(a.len(), b.len(), "bit_lt takes equal length bit arrays");

    // Invert `b`, add and then evaluate the carry
    let n = a.len();
    let ones = fabric.ones_authenticated(n);
    let b_inverted = AuthenticatedScalarResult::batch_sub(&ones, b);

    let carry = carry_out_public(a, &b_inverted, fabric.one_authenticated());

    Scalar::one() - carry
}

#[cfg(test)]
mod tests {
    use futures::future::join_all;
    use itertools::Itertools;
    use mpc_stark::{
        algebra::{authenticated_scalar::AuthenticatedScalarResult, scalar::Scalar},
        error::MpcError,
        PARTY0, PARTY1,
    };
    use num_bigint::BigUint;
    use rand::{thread_rng, Rng, RngCore};
    use test_helpers::mpc_network::execute_mock_mpc;

    use crate::mpc_gadgets::bits::{bit_lt, bit_lt_public, to_bits_le};

    use super::{scalar_from_bits_le, scalar_to_bits_le};

    #[tokio::test]
    async fn test_scalar_to_bits() {
        let (res, _) = execute_mock_mpc(|fabric| async move {
            let random_u64 = thread_rng().next_u64();
            let scalar = Scalar::from(random_u64);
            let mpc_val = fabric.allocate_scalar(scalar);

            let bits = scalar_to_bits_le::<64>(&mpc_val);

            let reconstructed = bits
                .iter()
                .rev()
                .fold(fabric.zero(), |acc, bit| acc * Scalar::from(2u64) + bit);

            scalar == reconstructed.await
        })
        .await;

        assert!(res);
    }

    #[tokio::test]
    async fn test_scalar_to_bits_all_one() {
        let (res, _) = execute_mock_mpc(|fabric| async move {
            const N: usize = 250; // Power of 2 to fills bits up to
            let scalar = (0..N).fold(Scalar::zero(), |acc, _| {
                acc * Scalar::from(2u64) + Scalar::from(1u64)
            });
            let allocated = fabric.allocate_scalar(scalar);

            let res = join_all(scalar_to_bits_le::<N>(&allocated)).await;
            let expected_bits = (0..N).map(|_| Scalar::one()).collect_vec();

            res == expected_bits
        })
        .await;

        assert!(res);
    }

    #[tokio::test]
    async fn test_scalar_from_bits() {
        let n = 251;

        let (party0_res, party1_res) = execute_mock_mpc(move |fabric| async move {
            let bits = {
                let mut rng = thread_rng();
                (0..n).map(|_| rng.gen_bool(0.5) as u64).collect_vec()
            }; // Drop `rng`, it is not `Send`

            // Party 0 shares their bits
            let random_scalar_bits = fabric.batch_share_scalar(bits, PARTY0);
            let res = scalar_from_bits_le(&random_scalar_bits);
            let res_open = res.open().await.to_biguint();

            // Open the bits separately and verify their result
            let bits_open =
                join_all(AuthenticatedScalarResult::open_batch(&random_scalar_bits)).await;
            let expected_res = bits_open
                .into_iter()
                .rev()
                .map(|s| s.to_biguint())
                .fold(BigUint::from(0u8), |acc, bit| acc * 2u8 + bit);

            expected_res == res_open
        })
        .await;

        assert!(party0_res);
        assert!(party1_res);
    }

    #[tokio::test]
    async fn test_scalar_from_bits_all_one() {
        let n = 250; // The number of bits to fill in as ones
        let scalar_bits = 256; // The number of bits used to store a Scalar

        let (party0_res, party1_res) = execute_mock_mpc(move |fabric| async move {
            let bits = fabric
                .ones_authenticated(n)
                .into_iter()
                .chain(fabric.zeros_authenticated(scalar_bits - n).into_iter())
                .collect::<Vec<_>>();

            let res = scalar_from_bits_le(&bits);
            let res_open = res.open().await.to_biguint();
            let expected_res = (0..n).fold(BigUint::from(0u64), |acc, _| acc * 2u8 + 1u8);

            res_open == expected_res
        })
        .await;

        assert!(party0_res);
        assert!(party1_res);
    }

    /// Tests the `bit_lt` gadget
    #[tokio::test]
    async fn test_bit_lt() {
        // The number of bits in the field
        const N: usize = 250;

        // Test the case in which the two values are equal
        let (party0_res, party1_res): (Result<bool, MpcError>, Result<bool, MpcError>) =
            execute_mock_mpc(|fabric| async move {
                let value = 10;
                let equal_value1 = fabric.share_scalar(value, PARTY0);
                let equal_value2 = fabric.share_scalar(value, PARTY1);

                let res = bit_lt(
                    &to_bits_le::<N>(&equal_value1, &fabric),
                    &to_bits_le::<N>(&equal_value2, &fabric),
                    &fabric,
                )
                .open_authenticated()
                .await?;

                Ok(res == Scalar::zero())
            })
            .await;

        assert!(party0_res.unwrap());
        assert!(party1_res.unwrap());

        // Test the case in which one value is less than the other
        let mut rng = thread_rng();
        let values = (rng.next_u64(), rng.next_u64());
        let min_value = u64::min(values.0, values.1);
        let max_value = u64::max(values.0, values.1);

        let (res, _): (Result<(bool, bool), MpcError>, _) =
            execute_mock_mpc(move |fabric| async move {
                let min_value = fabric.share_scalar(min_value, PARTY0);
                let max_value = fabric.share_scalar(max_value, PARTY1);

                let min_bits = to_bits_le::<N>(&min_value, &fabric);
                let max_bits = to_bits_le::<N>(&max_value, &fabric);

                // min_value < max_value == true
                let res1 = bit_lt(&min_bits, &max_bits, &fabric)
                    .open_authenticated()
                    .await?;

                // max_value < min_value == false
                let res2 = bit_lt(&max_bits, &min_bits, &fabric)
                    .open_authenticated()
                    .await?;

                Ok((res1 == Scalar::one(), res2 == Scalar::zero()))
            })
            .await;

        let (res1, res2) = res.unwrap();
        assert!(res1);
        assert!(res2);
    }

    /// Test the `bit_lt_public` method
    #[tokio::test]
    async fn test_bit_lt_public() {
        // The number of bits in the field
        const N: usize = 250;

        let mut rng = thread_rng();
        let values = (rng.next_u64(), rng.next_u64());
        let min_value = u64::min(values.0, values.1);
        let max_value = u64::max(values.0, values.1);

        let (res, _): (Result<(bool, bool), MpcError>, _) =
            execute_mock_mpc(move |fabric| async move {
                let min_value = fabric.share_scalar(min_value, PARTY0);
                let max_value = fabric.share_scalar(max_value, PARTY1);

                let min_bits = to_bits_le::<N>(&min_value, &fabric);
                let max_bits = to_bits_le::<N>(&max_value, &fabric);

                // min_value < max_value == true
                let min_bits_public = AuthenticatedScalarResult::open_batch(&min_bits);
                let res1 = bit_lt_public(&min_bits_public, &max_bits, &fabric)
                    .open_authenticated()
                    .await?;

                // max_value < min_value == false
                let max_bits_public = AuthenticatedScalarResult::open_batch(&max_bits);
                let res2 = bit_lt_public(&max_bits_public, &min_bits, &fabric)
                    .open_authenticated()
                    .await?;

                Ok((res1 == Scalar::one(), res2 == Scalar::zero()))
            })
            .await;

        let (res1, res2) = res.unwrap();
        assert!(res1);
        assert!(res2);
    }
}
