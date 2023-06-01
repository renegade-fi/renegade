//! Groups logic related to the match computation circuit

use curve25519_dalek::scalar::Scalar;
use mpc_ristretto::{
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource, network::MpcNetwork,
};

use crate::{
    errors::MpcError,
    mpc::SharedFabric,
    mpc_gadgets::comparators::min,
    types::{order::AuthenticatedOrder, r#match::AuthenticatedMatchResult, AMOUNT_BITS},
    zk_gadgets::fixed_point::AuthenticatedFixedPoint,
};

/// Executes a match computation that returns matches from a given order intersection
///
/// If no match is found, the values are opened to a zero'd list
///
/// We do not check whether the orders are valid and overlapping, this is left to the
/// `VALID MATCH MPC` circuit, which both parties verify before opening the match result.
/// So, if the match result is invalid, the orders don't overlap, etc; the result will
/// never be opened, and the information never leaked. Therefore, we do not need to zero
/// out any values in the circuit.
pub fn compute_match<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    order1: &AuthenticatedOrder<N, S>,
    order2: &AuthenticatedOrder<N, S>,
    amount1: &AuthenticatedScalar<N, S>,
    amount2: &AuthenticatedScalar<N, S>,
    price: &AuthenticatedFixedPoint<N, S>,
    fabric: SharedFabric<N, S>,
) -> Result<AuthenticatedMatchResult<N, S>, MpcError> {
    // Compute the amount and execution price that will be swapped if the orders match
    let (min_index, min_base_amount) = min::<AMOUNT_BITS, _, _>(amount1, amount2, fabric.clone())?;

    // The maximum of the two amounts minus the minimum of the two amounts
    let max_minus_min_amount =
        &order1.amount + &order2.amount - Scalar::from(2u64) * &min_base_amount;

    // The amount of quote token exchanged
    // Round down to the nearest integer value
    let quote_exchanged_fp = min_base_amount.clone() * price;
    let quote_exchanged = quote_exchanged_fp.as_integer(fabric)?;

    // Zero out the orders if any of the initial checks failed
    Ok(AuthenticatedMatchResult {
        quote_mint: order1.quote_mint.clone(),
        base_mint: order1.base_mint.clone(),
        quote_amount: quote_exchanged,
        base_amount: min_base_amount,
        direction: order1.side.clone(),
        max_minus_min_amount,
        min_amount_order_index: min_index,
    })
}
