//! Groups MPC gadgets centered around arithmetic operations

use circuit_types::{errors::MpcError, SharedFabric};
use curve25519_dalek::scalar::Scalar;
use mpc_ristretto::{
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource, network::MpcNetwork,
};

/// Computes the product of all elements in constant number of rounds
///     Result = a_0 * ... * a_n
pub fn product<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    a: &[AuthenticatedScalar<N, S>],
    fabric: SharedFabric<N, S>,
) -> Result<AuthenticatedScalar<N, S>, MpcError> {
    Ok(prefix_product_impl(a, fabric, &[a.len() - 1])?[0].clone())
}

/// Computes the prefix products of the given list of elements: i.e.
///     Returns [c_1, .., c_D] where c_i = \prod_{j=1}^i a_j
///
/// This implementation is done in a constant number of rounds according to:
/// https://iacr.org/archive/tcc2006/38760286/38760286.pdf
pub fn prefix_mul<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    a: &[AuthenticatedScalar<N, S>],
    fabric: SharedFabric<N, S>,
) -> Result<Vec<AuthenticatedScalar<N, S>>, MpcError> {
    prefix_product_impl(
        a,
        fabric,
        &(0usize..a.len()).collect::<Vec<_>>(), // Select all prefix products
    )
}

/// Provides a common implementation for computing the prefix products of a series for a given set
/// of prefixes
///
/// Prefixes are specified as a list pre = [pre_1, pre_2, ..., pre_k] where pre_l implies that the
/// method returns \prod_{i=0}^l a_i in the lth element of the return vector
///
/// Note that each additional prefix incurs more bandwidth (although constant round)
fn prefix_product_impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    a: &[AuthenticatedScalar<N, S>],
    fabric: SharedFabric<N, S>,
    pre: &[usize],
) -> Result<Vec<AuthenticatedScalar<N, S>>, MpcError> {
    let n = a.len();
    assert!(
        pre.iter().all(|x| x < &n),
        "All prefixes requested must be in range"
    );

    // Fetch one inverse pair per element from the pre-processing source
    let (b_values, b_inv_values) = fabric
        .borrow_fabric()
        .allocate_random_inverse_pair_batch(n + 1 /* num_inverses */)
        .into_iter()
        .unzip::<_, _, Vec<_>, Vec<_>>();

    // Using the inverse pairs (b_i, b_i^-1), compute d_i = b_{i-1} * a_i * b_i^-1
    // We will open these values and use them to form telescoping partial products wherein the only non-cancelled terms
    // are a b_{k-1} * b_k^-1
    let d_partial = AuthenticatedScalar::batch_mul(&b_values[..n], a)
        .map_err(|err| MpcError::ArithmeticError(err.to_string()))?;

    let d_values = AuthenticatedScalar::batch_mul(&d_partial, &b_inv_values[1..])
        .map_err(|err| MpcError::ArithmeticError(err.to_string()))?;

    // TODO: Can we just call `batch_open` here and simply authenticate at the end?
    let d_values_open = AuthenticatedScalar::batch_open(&d_values)
        .map_err(|_| MpcError::OpeningError("error opening d_values in prefix_mul".to_string()))?;

    // The partial products are formed by creating a series of telescoping products and then cancelling them out with the correct b_i values
    let mut partial_products = Vec::with_capacity(n);
    let mut accumulator = fabric.borrow_fabric().allocate_public_u64(1);
    for d_value in d_values_open.iter() {
        accumulator *= d_value;
        partial_products.push(accumulator.clone());
    }

    // Each partial product (after factors cancel) is of the form
    //      partial_i = b_{0} * a_0 * ... * a_i * b_i^-1
    // So it must be multiplied by b_{i-1}^-1 * b_i to create a secret sharing
    // of a_0 * ... * a_i.
    // To do so, we first batch multiply b_0^-1 * b_i for i > 0
    let cancellation_factors = AuthenticatedScalar::batch_mul(
        &vec![b_inv_values[0].clone(); pre.len()], // Each prefix product starts at 0
        &pre.iter()
            .map(|index| b_values[*index].clone())
            .collect::<Vec<_>>(),
    )
    .map_err(|err| MpcError::ArithmeticError(err.to_string()))?;

    let selected_partial_products = pre
        .iter()
        .map(|index| partial_products[*index].clone())
        .collect::<Vec<_>>();

    // No communication is required here, the partial_products are public and the
    // cancellation_factors are shared, so computation can be done locally.
    // Unwrap is therefore safe
    Ok(AuthenticatedScalar::batch_mul(&selected_partial_products, &cancellation_factors).unwrap())
}

/// Computes a^n using a recursive squaring approach for a public parameter exponent
pub fn pow<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    a: &AuthenticatedScalar<N, S>,
    n: u64,
    fabric: SharedFabric<N, S>,
) -> AuthenticatedScalar<N, S> {
    if n == 0 {
        fabric.borrow_fabric().allocate_zero()
    } else if n == 1 {
        a.clone()
    } else if n % 2 == 0 {
        let recursive_res = pow(a, n / 2, fabric);
        &recursive_res * &recursive_res
    } else {
        let recursive_res = pow(a, (n - 1) / 2, fabric);
        &recursive_res * &recursive_res * a
    }
}
