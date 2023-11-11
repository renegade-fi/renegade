//! Groups MPC gadgets centered around arithmetic operations

use circuit_types::Fabric;
use constants::AuthenticatedScalar;

/// Computes the product of all elements in constant number of rounds
///     Result = a_0 * ... * a_n
pub fn product(a: &[AuthenticatedScalar], fabric: &Fabric) -> AuthenticatedScalar {
    prefix_product_impl(a, &[a.len() - 1], fabric)[0].clone()
}

/// Computes the prefix products of the given list of elements: i.e.
///     Returns [c_1, .., c_D] where c_i = \prod_{j=1}^i a_j
///
/// This implementation is done in a constant number of rounds according to:
/// https://iacr.org/archive/tcc2006/38760286/38760286.pdf
pub fn prefix_mul(a: &[AuthenticatedScalar], fabric: &Fabric) -> Vec<AuthenticatedScalar> {
    prefix_product_impl(
        a,
        &(0usize..a.len()).collect::<Vec<_>>(), // Select all prefix products
        fabric,
    )
}

/// Provides a common implementation for computing the prefix products of a
/// series for a given set of prefixes
///
/// Prefixes are specified as a list pre = [pre_1, pre_2, ..., pre_k] where
/// pre_l implies that the method returns \prod_{i=0}^l a_i in the lth element
/// of the return vector
///
/// Note that each additional prefix incurs more bandwidth (although constant
/// round)
fn prefix_product_impl(
    a: &[AuthenticatedScalar],
    pre: &[usize],
    fabric: &Fabric,
) -> Vec<AuthenticatedScalar> {
    let n = a.len();
    assert!(
        pre.iter().all(|x| x < &n),
        "All prefixes requested must be in range"
    );

    // Fetch one inverse pair per element from the pre-processing source
    let (b_values, b_inv_values) = fabric.random_inverse_pairs(n + 1 /* num_inverses */);

    // Using the inverse pairs (b_i, b_i^-1), compute d_i = b_{i-1} * a_i * b_i^-1
    // We will open these values and use them to form telescoping partial products
    // wherein the only non-cancelled terms are a b_{k-1} * b_k^-1
    let d_partial = AuthenticatedScalar::batch_mul(&b_values[..n], a);
    let d_values = AuthenticatedScalar::batch_mul(&d_partial, &b_inv_values[1..]);

    // TODO: Can we just call `batch_open` here and simply authenticate at the end?
    let d_values_open = AuthenticatedScalar::open_batch(&d_values);

    // The partial products are formed by creating a series of telescoping products
    // and then cancelling them out with the correct b_i values
    let mut partial_products = Vec::with_capacity(n);
    let mut accumulator = fabric.one_authenticated();
    for d_value in d_values_open.iter() {
        accumulator = accumulator * d_value;
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
    );

    let selected_partial_products = pre
        .iter()
        .map(|index| partial_products[*index].clone())
        .collect::<Vec<_>>();

    // No communication is required here, the partial_products are public and the
    // cancellation_factors are shared, so computation can be done locally.
    // Unwrap is therefore safe
    AuthenticatedScalar::batch_mul(&selected_partial_products, &cancellation_factors)
}

/// Computes a^n using a recursive squaring approach for a public parameter
/// exponent
pub fn pow(a: &AuthenticatedScalar, n: u64, fabric: &Fabric) -> AuthenticatedScalar {
    if n == 0 {
        fabric.one_authenticated()
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

#[cfg(test)]
mod test {
    use ark_mpc::PARTY0;
    use constants::Scalar;
    use itertools::Itertools;
    use rand::{thread_rng, Rng};
    use test_helpers::mpc_network::execute_mock_mpc;

    use crate::{
        mpc_gadgets::arithmetic::{pow, prefix_mul},
        test_helpers::joint_open,
    };

    /// Tests the prefix product implementation
    #[tokio::test]
    async fn test_prefix_prod() {
        const N: usize = 10;

        let mut rng = thread_rng();
        let values = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();

        let expected = values
            .iter()
            .scan(Scalar::one(), |acc, x| {
                *acc = *acc * x;
                Some(*acc)
            })
            .collect_vec();

        let (res, _) = execute_mock_mpc(move |fabric| {
            let values = values.clone();
            async move {
                let shared_values = fabric.batch_share_scalar(values, PARTY0);
                let res = prefix_mul(&shared_values, &fabric);

                joint_open(res).await
            }
        })
        .await;

        assert_eq!(res.unwrap(), expected);
    }

    /// Tests the `pow` implementation
    #[tokio::test]
    async fn test_pow() {
        let mut rng = thread_rng();
        let base = Scalar::random(&mut rng);
        let exp = rng.gen();

        let expected = base.pow(exp);
        let (res, _) = execute_mock_mpc(move |fabric| async move {
            let shared_base = fabric.share_scalar(base, PARTY0);
            let res = pow(&shared_base, exp, &fabric);

            res.open_authenticated().await
        })
        .await;

        assert_eq!(res.unwrap(), expected);
    }
}
