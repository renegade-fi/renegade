//! Groups MPC gadgets centered around arithmetic operations

use curve25519_dalek::scalar::Scalar;
use mpc_ristretto::{
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource, network::MpcNetwork,
};

use crate::{errors::MpcError, mpc::SharedFabric};

/// Computes the prefix products of the given list of elements: i.e.
///     Returns [c_1, .., c_D] where c_i = \prod_{j=1^i} a_j
///
/// This implementation is done in a constant number of rounds according to:
/// https://iacr.org/archive/tcc2006/38760286/38760286.pdf
pub fn prefix_mul<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    a: &[AuthenticatedScalar<N, S>],
    fabric: SharedFabric<N, S>,
) -> Result<Vec<AuthenticatedScalar<N, S>>, MpcError> {
    let n = a.len();

    // Fetch one inverse pair per element from the pre-procee sour
    let (b_values, b_inv_values) = fabric
        .borrow_fabric()
        .allocate_random_inverse_pair_batch(n + 1) // Fetch n + 1 random inverses
        .into_iter()
        .unzip::<_, _, Vec<_>, Vec<_>>();

    // Using the inverse pairs (b_i, b_i^-1), compute d_i = b_{i-1} * a_i * b_i^-1
    // We will open these values and use them to form telescoping partial products wherein the only non-cancelled terms
    // are a b_{k-1} * b_k^-1
    let d_partial = AuthenticatedScalar::batch_mul(&b_values[..n], a)
        .map_err(|err| MpcError::ArithmeticError(format!("{:?}", err)))?;

    let d_values = AuthenticatedScalar::batch_mul(&d_partial, &b_inv_values[1..])
        .map_err(|err| MpcError::ArithmeticError(format!("{:?}", err)))?;

    let d_values_open = AuthenticatedScalar::batch_open_and_authenticate(&d_values)
        .map_err(|_| MpcError::OpeningError("error opening d_values in prefix_mul".to_string()))?;

    // The partial products are formed by creating a series of telescoping products and then cancelling them out with the correct b_i values
    let mut partial_products = Vec::with_capacity(n);
    let mut accumulator = fabric.borrow_fabric().allocate_public_u64(1);
    for d_value in d_values_open.iter() {
        accumulator = accumulator * d_value;
        partial_products.push(accumulator.clone());
    }

    // Each partial product (after factors cancel) is of the form
    //      partial_i = b_{i-1} * a_0 * ... * a_i * b_i^-1
    // So it must be multiplied by b_{i-1}^-1 * b_i to create a secret sharing
    // of a_0 * ... * a_i.
    // To do so, we first batch multiply b_0^-1 * b_i for i > 0
    let cancellation_factors = AuthenticatedScalar::batch_mul(&b_inv_values[..n], &b_values[1..])
        .map_err(|err| MpcError::ArithmeticError(format!("{:?}", err)))?;

    // No communication is required here, the partial_products are public and the
    // cancellation_factors are shared, so computation can be done locally.
    // Unwrap is therefore safe
    Ok(AuthenticatedScalar::batch_mul(&partial_products, &cancellation_factors).unwrap())
}
