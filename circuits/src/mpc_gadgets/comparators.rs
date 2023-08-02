//! Groups logic around arithmetic comparator circuits

use std::iter;

use mpc_stark::{
    algebra::{authenticated_scalar::AuthenticatedScalarResult, scalar::Scalar},
    MpcFabric,
};

use super::{
    arithmetic::product,
    bits::{bit_xor_public, scalar_from_bits_le, scalar_to_bits_le, to_bits_le},
    modulo::truncate,
};

/// Implements the comparator a < 0
///
/// D represents is the bitlength of the input
pub fn less_than_zero<const D: usize>(
    a: &AuthenticatedScalarResult,
    fabric: MpcFabric,
) -> AuthenticatedScalarResult {
    // Truncate the first 250 bits of the input
    let truncated = truncate::<250>(a, fabric.clone());

    // Because the Ristretto scalar field is a prime field of order slightly greater than 2^252
    // values are negative if either their 251st bit or 252nd bit are set. Therefore, we truncate
    // all bits below this and compare the value to zero.
    ne::<2 /* bit_length */>(&truncated, &fabric.zero_authenticated(), fabric)
}

/// Implements the comparator a == 0
///
/// D represents the bitlength of the input
pub fn eq_zero<const D: usize>(
    a: &AuthenticatedScalarResult,
    fabric: MpcFabric,
) -> AuthenticatedScalarResult {
    let bits = to_bits_le::<D>(a, fabric.clone());
    Scalar::one() - kary_or::<D>(&bits.try_into().unwrap(), fabric)
}

/// Implements the comparator a == b
///
/// D represents the bitlength of the inputs
pub fn eq<const D: usize>(
    a: &AuthenticatedScalarResult,
    b: &AuthenticatedScalarResult,
    fabric: MpcFabric,
) -> AuthenticatedScalarResult {
    eq_zero::<D>(&(a - b), fabric)
}

/// Implements the comparator a != b
///
/// D represents the bitlength of the inputs
pub fn ne<const D: usize>(
    a: &AuthenticatedScalarResult,
    b: &AuthenticatedScalarResult,
    fabric: MpcFabric,
) -> AuthenticatedScalarResult {
    Scalar::one() - eq::<D>(a, b, fabric)
}

/// Implements the comparator a < b
///
/// D represents the bitlength of a and b
pub fn less_than<const D: usize>(
    a: &AuthenticatedScalarResult,
    b: &AuthenticatedScalarResult,
    fabric: MpcFabric,
) -> AuthenticatedScalarResult {
    less_than_zero::<D>(&(a - b), fabric)
}

/// Implements the comparator a <= b
///
/// D represents the bitlength of a and b
pub fn less_than_equal<const D: usize>(
    a: &AuthenticatedScalarResult,
    b: &AuthenticatedScalarResult,
    fabric: MpcFabric,
) -> AuthenticatedScalarResult {
    Scalar::one() - greater_than::<D>(a, b, fabric)
}

/// Implements the comparator a > b
///
/// D represents the bitlength of a and b
pub fn greater_than<const D: usize>(
    a: &AuthenticatedScalarResult,
    b: &AuthenticatedScalarResult,
    fabric: MpcFabric,
) -> AuthenticatedScalarResult {
    less_than_zero::<D>(&(b - a), fabric)
}

/// Implements the comparator a >= b
///
/// D represents the bitlength of a and b
pub fn greater_than_equal<const D: usize>(
    a: &AuthenticatedScalarResult,
    b: &AuthenticatedScalarResult,
    fabric: MpcFabric,
) -> AuthenticatedScalarResult {
    Scalar::one() - less_than::<D>(a, b, fabric)
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
pub fn kary_or<const D: usize>(
    a: &[AuthenticatedScalarResult; D],
    fabric: MpcFabric,
) -> AuthenticatedScalarResult {
    // Sample random blinding bits from the pre-processing functionality
    // We only need to be able to hold the maximum possible count, log_2(# of booleans)
    let max_bits = ((a.len() + 1) as f32).log2().ceil() as usize;
    let blinding_bits = fabric.random_shared_bits(max_bits);
    let blinding_value = scalar_from_bits_le(&blinding_bits);
    let blinding_value_upper_bits = Scalar::from((1 << max_bits) as u64)
        * &fabric.random_shared_scalars_authenticated(1 /* n */)[0];

    // Blind the sum of all booleans and open the result
    let sum_a: AuthenticatedScalarResult = a.iter().cloned().sum();
    let blinded_sum: AuthenticatedScalarResult =
        &sum_a + &blinding_value + &blinding_value_upper_bits;

    let blinded_sum_open = blinded_sum.open_authenticated();

    // Decompose the blinded sum into bits
    let blinded_sum_bits = scalar_to_bits_le::<D>(&blinded_sum_open.value);

    // XOR the blinded sum bits with the blinding bits that are still shared to obtain a sharing of the
    // sum bits (unblinded)
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
fn constant_round_or_impl(
    a: &[AuthenticatedScalarResult],
    fabric: MpcFabric,
) -> AuthenticatedScalarResult {
    // Sum up the booleans
    let n = a.len();
    let sum_a: AuthenticatedScalarResult = a.iter().cloned().sum();

    // Compute (1 - sum) * (2 - sum) * ... * (n - sum) / n!
    // We wrap the n! in implicitly here to avoid overflow computing n! directly for large n
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
pub fn min<const D: usize>(
    a: &AuthenticatedScalarResult,
    b: &AuthenticatedScalarResult,
    fabric: MpcFabric,
) -> (AuthenticatedScalarResult, AuthenticatedScalarResult) {
    let a_lt_b = less_than::<D>(a, b, fabric);
    (
        Scalar::from(1u64) - a_lt_b.clone(),
        &a_lt_b * a + (Scalar::one() - a_lt_b) * b,
    )
}

/// Computes res = a if s else b
pub fn cond_select(
    s: &AuthenticatedScalarResult,
    a: &AuthenticatedScalarResult,
    b: &AuthenticatedScalarResult,
) -> AuthenticatedScalarResult {
    let selectors = AuthenticatedScalarResult::batch_mul(
        &[a.clone(), b.clone()],
        &[s.clone(), Scalar::one() - s],
    );

    &selectors[0] + &selectors[1]
}

/// Computes res = [a] if s else [b] where a and b are slices
pub fn cond_select_vec(
    s: &AuthenticatedScalarResult,
    a: &[AuthenticatedScalarResult],
    b: &[AuthenticatedScalarResult],
) -> Vec<AuthenticatedScalarResult> {
    assert_eq!(
        a.len(),
        b.len(),
        "cond_select_vec requires equal length vectors"
    );
    // Batch mul each a value with `s` and each `b` value with 1 - s
    let selectors = AuthenticatedScalarResult::batch_mul(
        &a.iter()
            .cloned()
            .chain(b.iter().cloned())
            .collect::<Vec<_>>(),
        &iter::repeat(s.clone())
            .take(a.len())
            .chain(iter::repeat(Scalar::one() - s).take(b.len()))
            .collect::<Vec<_>>(),
    );

    // Destruct the vector by zipping its first half with its second half
    let mut result = Vec::with_capacity(a.len());
    for (a_selected, b_selected) in selectors[..a.len()]
        .as_ref()
        .iter()
        .zip(selectors[a.len()..].iter())
    {
        result.push(a_selected + b_selected)
    }

    result
}
