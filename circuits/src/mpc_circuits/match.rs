//! Groups logic related to the match computation circuit

use curve25519_dalek::scalar::Scalar;
use mpc_ristretto::{
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource, network::MpcNetwork,
};

use crate::{
    errors::MpcError,
    mpc::SharedFabric,
    mpc_gadgets::{
        arithmetic::product,
        comparators::{cond_select_vec, eq, less_than_equal, min, ne},
    },
    types::{
        order::AuthenticatedOrder,
        r#match::{AuthenticatedMatchResult, MATCH_SIZE_SCALARS},
    },
    zk_gadgets::fixed_point::AuthenticatedFixedPoint,
};

/// Executes a match computation that returns matches from a given order intersection
///
/// If no match is found, the values are opened to a zero'd list
pub fn compute_match<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    order1: &AuthenticatedOrder<N, S>,
    order2: &AuthenticatedOrder<N, S>,
    fabric: SharedFabric<N, S>,
) -> Result<AuthenticatedMatchResult<N, S>, MpcError> {
    // Check that the crossing orders are for the same asset pair
    let equal_mint1 = eq::<64, _, _>(&order1.base_mint, &order2.base_mint, fabric.clone())?;
    let equal_mint2 = eq::<64, _, _>(&order1.quote_mint, &order2.quote_mint, fabric.clone())?;

    // Check that the sell side price is below the buy side
    let price_overlap = price_overlap(order1, order2, fabric.clone())?;

    // Check that the orders are on opposite sides of the book
    let opposite_sides = ne::<64, _, _>(&order1.side, &order2.side, fabric.clone())?;

    // Aggregate all the checks into a single boolean, each check should be equal to 1 for a valid match
    let aggregate_check = product(
        &[equal_mint1, equal_mint2, price_overlap, opposite_sides],
        fabric.clone(),
    )?;

    // Compute the amount and execution price that will be swapped if the above checks pass
    let (min_index, min_base_amount) =
        min::<32, _, _>(&order1.amount, &order2.amount, fabric.clone())?;

    // The maximum of the two amounts minus the minimum of the two amounts
    let max_minus_min_amount =
        &order1.amount + &order2.amount - Scalar::from(2u64) * &min_base_amount;

    // Compute execution price = (price1 + price2) / 2
    let one_half = AuthenticatedFixedPoint::from_public_f32(0.5, fabric.clone());
    let execution_price = &(&order1.price + &order2.price) * &one_half;

    // The amount of quote token exchanged
    // Round down to the nearest integer value
    let quote_exchanged_fp = min_base_amount.clone() * &execution_price;
    let quote_exchanged = quote_exchanged_fp.as_integer(fabric.clone())?;

    // Zero out the orders if any of the initial checks failed
    let masked_output = cond_select_vec(
        &aggregate_check,
        &[
            order1.quote_mint.clone(),
            order1.base_mint.clone(),
            quote_exchanged,
            min_base_amount, // Base amount exchanged
            order1.side.clone(),
            execution_price.repr,
            max_minus_min_amount,
            min_index,
        ],
        &fabric
            .borrow_fabric()
            .allocate_zeros(MATCH_SIZE_SCALARS /* num_zeros */),
    )
    .map_err(|err| MpcError::ArithmeticError(err.to_string()))?;

    Ok(AuthenticatedMatchResult {
        quote_mint: masked_output[0].to_owned(),
        base_mint: masked_output[1].to_owned(),
        quote_amount: masked_output[2].to_owned(),
        base_amount: masked_output[3].to_owned(),
        direction: masked_output[4].to_owned(),
        execution_price: AuthenticatedFixedPoint {
            repr: masked_output[5].to_owned(),
        },
        max_minus_min_amount: masked_output[6].to_owned(),
        min_amount_order_index: masked_output[7].to_owned(),
    })
}

/// Computes whether the prices of two orders overlap
///
/// Returns the result as a boolean encoded as an AuthenticatedScalar
fn price_overlap<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    order1: &AuthenticatedOrder<N, S>,
    order2: &AuthenticatedOrder<N, S>,
    fabric: SharedFabric<N, S>,
) -> Result<AuthenticatedScalar<N, S>, MpcError> {
    // Mux between orders as sell and buy side
    let selected_prices = cond_select_vec(
        &order1.side,
        &[order2.price.repr.clone(), order1.price.repr.clone()],
        &[order1.price.repr.clone(), order2.price.repr.clone()],
    )?;

    let buy_side_price = &selected_prices[0];
    let sell_side_price = &selected_prices[1];

    less_than_equal::<64, _, _>(sell_side_price, buy_side_price, fabric)
}
