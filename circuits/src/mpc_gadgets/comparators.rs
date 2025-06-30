//! Groups logic around arithmetic comparator circuits

use ark_mpc::gadgets::bit_xor_public;
use circuit_types::{AuthenticatedBool, Fabric};
use constants::{AuthenticatedScalar, Scalar};
use itertools::Itertools;

use crate::SCALAR_BITS_MINUS_TWO;

use super::{
    arithmetic::product,
    bits::{scalar_from_bits_le, scalar_to_bits_le, to_bits_le},
    modulo::truncate,
};

/// Implements the comparator a < 0
///
/// D represents is the bitlength of the input values
///
/// Note that this definition is only correct if we allow for positive values
/// only up to 252 bits. This is because we define a scalar as negative if it
/// is greater than (p-1)/2, then for our 254 bit prime, this threshold sits
/// between values 2^252 and 2^253. Therefore, our method of truncation and
/// top-two bit check will fail for values 2^252 <= x < (p-1) / 2
///
/// So we enforce that the values are less than 2^252
pub fn less_than_zero(a: &AuthenticatedScalar, fabric: &Fabric) -> AuthenticatedScalar {
    // Truncate the first `SCALAR_BITS_MINUS_TWO` bits of the input
    let truncated = truncate(a, SCALAR_BITS_MINUS_TWO, fabric);

    // Because the scalar field (Bn254) is a prime field of order greater than
    // 2^253, values are negative if either their 253rd bit or 254th bit are set.
    // Therefore, we truncate all bits below this and compare the value to zero.
    let num_bits = 2;
    ne(&truncated, &fabric.zero_authenticated(), num_bits, fabric)
}

/// Implements the comparator a == 0
///
/// D represents the bitlength of the input
pub fn eq_zero(a: &AuthenticatedScalar, num_bits: usize, fabric: &Fabric) -> AuthenticatedScalar {
    let bits = to_bits_le(a, num_bits, fabric);
    Scalar::one() - kary_or(&bits, fabric)
}

/// Implements the comparator a == b
///
/// D represents the bitlength of the inputs
pub fn eq(
    a: &AuthenticatedScalar,
    b: &AuthenticatedScalar,
    num_bits: usize,
    fabric: &Fabric,
) -> AuthenticatedScalar {
    let diff = a - b;
    eq_zero(&diff, num_bits, fabric)
}

/// Implements the comparator a != b
///
/// D represents the bitlength of the inputs
pub fn ne(
    a: &AuthenticatedScalar,
    b: &AuthenticatedScalar,
    num_bits: usize,
    fabric: &Fabric,
) -> AuthenticatedScalar {
    Scalar::one() - eq(a, b, num_bits, fabric)
}

/// Implements the comparator a < b
///
/// D represents the bitlength of a and b
pub fn less_than(
    a: &AuthenticatedScalar,
    b: &AuthenticatedScalar,
    fabric: &Fabric,
) -> AuthenticatedScalar {
    less_than_zero(&(a - b), fabric)
}

/// Implements the comparator a <= b
///
/// D represents the bitlength of a and b
pub fn less_than_equal(
    a: &AuthenticatedScalar,
    b: &AuthenticatedScalar,
    fabric: &Fabric,
) -> AuthenticatedScalar {
    Scalar::one() - greater_than(a, b, fabric)
}

/// Implements the comparator a > b
///
/// D represents the bitlength of a and b
pub fn greater_than(
    a: &AuthenticatedScalar,
    b: &AuthenticatedScalar,
    fabric: &Fabric,
) -> AuthenticatedScalar {
    less_than_zero(&(b - a), fabric)
}

/// Implements the comparator a >= b
///
/// D represents the bitlength of a and b
pub fn greater_than_equal(
    a: &AuthenticatedScalar,
    b: &AuthenticatedScalar,
    fabric: &Fabric,
) -> AuthenticatedScalar {
    Scalar::one() - less_than(a, b, fabric)
}

/// Implements a k-ary Or comparator; i.e. a_1 || a_2 || ... || a_n
///
/// This method works as follows to achieve a constant round scheme:
///     1. Sum the a_i values
///     2. Blind this sum, open the blinded value, and decompose to bits
///     3. xor the bits with their blinding bits to recover shared bits
///     4. Compute an "or" over the recovered bits
///
/// `D` is the number of variables present in the OR expression
pub fn kary_or(a: &[AuthenticatedScalar], fabric: &Fabric) -> AuthenticatedScalar {
    let num_bits = a.len();

    // Sample random blinding bits from the pre-processing functionality
    // We only need to be able to hold the maximum possible count, log_2(# of
    // booleans)
    let max_bits = ((a.len() + 1) as f32).log2().ceil() as usize;
    let blinding_bits = fabric.random_shared_bits(max_bits);
    let blinding_value = scalar_from_bits_le(&blinding_bits);
    let blinding_value_upper_bits =
        Scalar::from((1 << max_bits) as u64) * &fabric.random_shared_scalars(1 /* n */)[0];

    // Blind the sum of all booleans and open the result
    let sum_a: AuthenticatedScalar = a.iter().cloned().sum();
    let blinded_sum: AuthenticatedScalar = &sum_a + &blinding_value + &blinding_value_upper_bits;

    let blinded_sum_open = blinded_sum.open_authenticated();

    // Decompose the blinded sum into bits
    let blinded_sum_bits = scalar_to_bits_le(&blinded_sum_open.value, num_bits);

    // XOR the blinded sum bits with the blinding bits that are still shared to
    // obtain a sharing of the sum bits (unblinded)
    let unblinded_shared_bits = blinded_sum_bits
        .into_iter()
        .zip(blinding_bits.iter())
        .map(|(blinded_bit, blinder_bit)| bit_xor_public(&blinded_bit, blinder_bit))
        .collect::<Vec<_>>();

    constant_round_or_impl(&unblinded_shared_bits, fabric)
}

// TODO: Optimize this into parallel blocks for larger length inputs
/// Computes the "OR" of all input bits using a public polynomial.
///
/// Specifically, the method evaluates the polynomial:
///     f(x) = 1/n! * (1 - x) * (2 - x) * ... * (n - x)
/// which is zero at 1..n and 1 at 0. Then we take 1 - f(x) to flip the result
///
/// This effectively maps any non-zero count to 1 and zero to 0
fn constant_round_or_impl(a: &[AuthenticatedScalar], fabric: &Fabric) -> AuthenticatedScalar {
    // Sum up the booleans
    let n = a.len();
    let sum_a: AuthenticatedScalar = a.iter().cloned().sum();

    // Compute (1 - sum) * (2 - sum) * ... * (n - sum) / n!
    // We wrap the n! in implicitly here to avoid overflow computing n! directly for
    // large n
    let sum_monomials = (1..n + 1)
        .map(|x| (Scalar::from(x as u64) - &sum_a) * Scalar::from(x as u64).inverse())
        .collect::<Vec<_>>();
    let monomial_product = product(&sum_monomials, fabric);

    // Flip the result
    Scalar::one() - monomial_product
}

/// TODO: Optimize this method
/// Computes the min of two scalars
///
/// Returns the minimum element and the index of the minimum, i.e.
/// if the a < b then 0 else 1
///
/// D represents the bitlength of a and b
#[allow(clippy::type_complexity)]
pub fn min(
    a: &AuthenticatedScalar,
    b: &AuthenticatedScalar,
    fabric: &Fabric,
) -> (AuthenticatedScalar, AuthenticatedScalar) {
    let a_lt_b = less_than(a, b, fabric);
    (Scalar::from(1u64) - a_lt_b.clone(), &a_lt_b * a + (Scalar::one() - a_lt_b) * b)
}

/// Computes res = a if s else b
pub fn cond_select(
    s: &AuthenticatedBool,
    a: &AuthenticatedScalar,
    b: &AuthenticatedScalar,
) -> AuthenticatedScalar {
    let selector: AuthenticatedScalar = s.clone().into();
    let terms = AuthenticatedScalar::batch_mul(
        &[a.clone(), b.clone()],
        &[selector.clone(), Scalar::one() - &selector],
    );

    &terms[0] + &terms[1]
}

/// Computes res = [a] if s else [b] where a and b are slices
pub fn cond_select_vec(
    s: &AuthenticatedBool,
    a: &[AuthenticatedScalar],
    b: &[AuthenticatedScalar],
) -> Vec<AuthenticatedScalar> {
    assert_eq!(a.len(), b.len(), "cond_select_vec requires equal length vectors");

    // Batch mul each a value with `s` and each `b` value with 1 - s
    let n = a.len();
    let selector: AuthenticatedScalar = s.clone().into();
    let terms = AuthenticatedScalar::batch_mul(
        &a.iter().cloned().chain(b.iter().cloned()).collect::<Vec<_>>(),
        &std::iter::repeat_n(selector.clone(), n)
            .chain(std::iter::repeat_n(Scalar::one() - &selector, n))
            .collect_vec(),
    );

    // Destruct the vector by zipping its first half with its second half
    let mut result = Vec::with_capacity(a.len());
    for (a_selected, b_selected) in terms[..a.len()].as_ref().iter().zip(terms[a.len()..].iter()) {
        result.push(a_selected + b_selected)
    }

    result
}

#[cfg(test)]
mod test {
    use std::ops::Neg;

    use ark_mpc::PARTY0;
    use circuit_types::traits::MpcBaseType;
    use constants::Scalar;
    use itertools::Itertools;
    use num_bigint::RandBigInt;
    use rand::{Rng, RngCore, thread_rng};
    use renegade_crypto::fields::biguint_to_scalar;
    use test_helpers::mpc_network::execute_mock_mpc;

    use crate::{
        SCALAR_MAX_BITS,
        mpc_gadgets::comparators::{
            cond_select, cond_select_vec, eq, greater_than, greater_than_equal, less_than,
            less_than_equal, less_than_zero, min, ne,
        },
        open_unwrap, open_unwrap_vec,
    };

    /// Tests the `lt_zero` gadget
    #[tokio::test]
    async fn test_lt_zero() {
        let mut rng = thread_rng();
        let inner = rng.gen_biguint(252 /* bit_size */);
        let val = biguint_to_scalar(&inner);

        // A value is negative if its additive inverse is smaller, i.e. it is greater
        // than half the field size
        let expected = val.inner() > val.neg().inner();

        let (res, _) = execute_mock_mpc(move |fabric| async move {
            let shared_val = fabric.share_scalar(val, PARTY0);
            less_than_zero(&shared_val, &fabric).open_authenticated().await
        })
        .await;

        assert_eq!(res.unwrap(), Scalar::from(expected))
    }

    /// Tests the equal gadgets
    #[tokio::test]
    #[rustfmt::skip]
    async fn test_eq_gadgets() {
        let mut rng = thread_rng();
        const BITS: usize = SCALAR_MAX_BITS - 2;
        let a = Scalar::from(rng.next_u64());
        let b = Scalar::from(rng.next_u64());

        let (success, _) = execute_mock_mpc(move |fabric| async move {
            let a_shared = fabric.share_scalar(a, PARTY0);
            let b_shared = fabric.share_scalar(b, PARTY0);
            let zero = fabric.zero_authenticated();

            let mut success = open_unwrap!(eq(&a_shared, &b_shared, BITS, &fabric)) == Scalar::zero(); // a == b
            success &= open_unwrap!(ne(&a_shared, &b_shared, BITS, &fabric)) == Scalar::one(); // a != b 
            success &= open_unwrap!(eq(&a_shared, &a_shared, BITS, &fabric)) == Scalar::one(); // a == a 
            success &= open_unwrap!(ne(&a_shared, &a_shared, BITS, &fabric)) == Scalar::zero(); // a != a
            success &= open_unwrap!(eq(&a_shared, &zero, BITS, &fabric)) == Scalar::zero(); // a == 0 
            success &= open_unwrap!(ne(&a_shared, &zero, BITS, &fabric)) == Scalar::one(); // a != 0
            success &= open_unwrap!(eq(&zero, &zero, BITS, &fabric)) == Scalar::one(); // 0 == 0

            success
        })
        .await;

        assert!(success);
    }

    /// Tests <, <=, >, >= gadgets
    #[tokio::test]
    #[rustfmt::skip]
    async fn test_comparator_gadgets() {
        let mut rng = thread_rng();
        let a = Scalar::from(rng.next_u64());
        let b = Scalar::from(rng.next_u64());

        // Whether a < b, as a scalar
        let ordering = Scalar::from(a.inner() < b.inner());

        let (success, _) = execute_mock_mpc(move |fabric| async move {
            let a = fabric.share_scalar(a, PARTY0);
            let b = fabric.share_scalar(b, PARTY0);

            // < and <=
            let mut success = open_unwrap!(less_than(&a, &b, &fabric)) == ordering; // a < b
            success &= open_unwrap!(less_than_equal(&a, &b, &fabric)) == ordering; // a <= b
            success &= open_unwrap!(less_than(&b, &a, &fabric)) != ordering; // b < a
            success &= open_unwrap!(less_than_equal(&b, &a, &fabric)) != ordering; // b <= a
            success &= open_unwrap!(less_than_equal(&a, &a, &fabric)) == Scalar::one(); // a <= a

            // > and >=
            success &= open_unwrap!(greater_than(&a, &b, &fabric)) != ordering; // a > b
            success &= open_unwrap!(greater_than_equal(&a, &b, &fabric)) != ordering; // a >= b
            success &= open_unwrap!(greater_than(&b, &a, &fabric)) == ordering; // b > a
            success &= open_unwrap!(greater_than_equal(&b, &a, &fabric)) == ordering; // b >= a
            success &= open_unwrap!(greater_than_equal(&a, &a, &fabric)) == Scalar::one(); // a >= a

            success
        })
        .await;

        assert!(success);
    }

    /// Tests the min gadget
    #[tokio::test]
    async fn test_min() {
        let mut rng = thread_rng();
        let a = Scalar::from(rng.next_u64());
        let b = Scalar::from(rng.next_u64());

        let (expected_idx, expected_min) =
            if a.inner() < b.inner() { (Scalar::zero(), a) } else { (Scalar::one(), b) };

        let ((min_idx, min), _) = execute_mock_mpc(move |fabric| async move {
            let a = fabric.share_scalar(a, PARTY0);
            let b = fabric.share_scalar(b, PARTY0);

            let (min_index, min) = min(&a, &b, &fabric);
            (open_unwrap!(min_index), open_unwrap!(min))
        })
        .await;

        assert_eq!(min_idx, expected_idx);
        assert_eq!(min, expected_min);
    }

    /// Test the cond select gadget
    #[tokio::test]
    async fn test_cond_select() {
        let mut rng = thread_rng();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        let s = rng.gen_bool(0.5);

        let expected = if s { a } else { b };

        let (res, _) = execute_mock_mpc(move |fabric| async move {
            let a = a.allocate(PARTY0, &fabric);
            let b = b.allocate(PARTY0, &fabric);
            let s = s.allocate(PARTY0, &fabric);

            let res = cond_select(&s, &a, &b);

            open_unwrap!(res)
        })
        .await;

        assert_eq!(res, expected)
    }

    /// Test the cond select vector gadget
    #[tokio::test]
    async fn test_cond_select_vec() {
        const N: usize = 10;
        let mut rng = thread_rng();

        let a = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();
        let b = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();
        let s = rng.gen_bool(0.5);

        let expected = if s { a.clone() } else { b.clone() };

        let (res, _) = execute_mock_mpc(move |fabric| {
            let a = a.clone();
            let b = b.clone();
            async move {
                let a = fabric.batch_share_scalar(a, PARTY0);
                let b = fabric.batch_share_scalar(b, PARTY0);
                let s = s.allocate(PARTY0, &fabric);

                let res = cond_select_vec(&s, &a, &b);

                open_unwrap_vec!(res)
            }
        })
        .await;

        assert_eq!(res, expected)
    }
}
