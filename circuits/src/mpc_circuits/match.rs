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
        modulo::shift_right,
    },
    types::{AuthenticatedMatch, AuthenticatedOrder, AuthenticatedSingleMatchResult},
};

/// Executes a match computation that returns matches from a given order intersection
///
/// If no match is found, the values are opened to a zero'd list
/// TODO: Remove these lint allowances
#[allow(unused_variables, clippy::redundant_clone)]
pub fn compute_match<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    order1: &AuthenticatedOrder<N, S>,
    order2: &AuthenticatedOrder<N, S>,
    fabric: SharedFabric<N, S>,
) -> Result<AuthenticatedSingleMatchResult<N, S>, MpcError> {
    // Check that the crossing orders are for the same asset pair
    let equal_mint1 = eq::<64, _, _>(&order1.base_mint, &order2.base_mint, fabric.clone())?;
    let equal_mint2 = eq::<64, _, _>(&order1.quote_mint, &order2.quote_mint, fabric.clone())?;

    // Check that the sell side price is below the buy side
    let price_overlap = price_overlap(order1, order2, fabric.clone())?;

    // Check that the orders are on oppostie sides of the book
    let opposite_sides = ne::<64, _, _>(&order1.side, &order2.side, fabric.clone())?;

    // Aggregate all the checks into a single boolean, each check should be equal to 1 for a valid match
    let aggregate_check = product(
        &[equal_mint1, equal_mint2, price_overlap, opposite_sides],
        fabric.clone(),
    )?;

    // Compute the amount and execution price that will be swapped if the above checks pass
    let min_amount = min::<32, _, _>(&order1.amount, &order2.amount, fabric.clone())?;

    // Compute execution price = (price1 + price2) / 2
    let execution_price = shift_right::<1, _, _>(&(&order1.price + &order2.price), fabric.clone())?;

    // The amount of quote token exchanged
    let quote_exchanged = &min_amount * &execution_price;

    // If order1 is buy side, buy_side1 will buy the base token and sell_side1 will sell the quote token
    // If order1 is sell side, buy_side1 will buy the quote token and sell_side1 will sell the base token
    let buy_side_selections = vec![
        order1.base_mint.clone(),  // Buy side mint
        min_amount.clone(),        // Buy side amount
        order1.quote_mint.clone(), // Sell side mint
        quote_exchanged.clone(),   // Sell side amount
    ];
    let sell_side_selections = vec![
        order1.quote_mint.clone(),
        quote_exchanged.clone(),
        order1.base_mint.clone(),
        min_amount.clone(),
    ];

    let order1_selections =
        cond_select_vec(&order1.side, &sell_side_selections, &buy_side_selections)
            .map_err(|err| MpcError::ArithmeticError(err.to_string()))?;

    // Zero out the orders if any of the initial checks failed
    let masked_order_selections = cond_select_vec(
        &aggregate_check,
        &order1_selections,
        &fabric.borrow_fabric().allocate_zeros(4 /* num_zeros */),
    )
    .map_err(|err| MpcError::ArithmeticError(err.to_string()))?;

    // Select the buy and sell sides for both parties
    // The buy result for the first party
    let buy_side1 = AuthenticatedMatch {
        mint: masked_order_selections[0].clone(),
        amount: masked_order_selections[1].clone(),
        side: fabric.borrow_fabric().allocate_public_u64(0 /* value */), // buy
    };

    // The sell result for the first party
    let sell_side1 = AuthenticatedMatch {
        mint: masked_order_selections[2].clone(),
        amount: masked_order_selections[3].clone(),
        side: fabric.borrow_fabric().allocate_public_u64(1 /* value */), // sell
    };

    // The buy side result for the second party
    let buy_side2 = AuthenticatedMatch {
        mint: masked_order_selections[2].clone(),
        amount: masked_order_selections[3].clone(),
        side: fabric.borrow_fabric().allocate_public_u64(0 /* value */), // buy
    };

    // The sell side result for the second party
    let sell_side2 = AuthenticatedMatch {
        mint: masked_order_selections[0].clone(),
        amount: masked_order_selections[1].clone(),
        side: fabric.borrow_fabric().allocate_public_u64(1 /* value */), // sell
    };

    Ok(AuthenticatedSingleMatchResult {
        buy_side1,
        sell_side1,
        buy_side2,
        sell_side2,
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
    // We require that the sell order has a price less than or equal to the buy
    // order. This is equivalent to:
    //      (order1.side == sell) == (order1.price <= order2.price)
    let order1_sell = &order1.side;
    let price1_lt_price2 =
        less_than_equal::<64, _, _>(&order1.price, &order2.price, fabric.clone())?;

    eq::<1, _, _>(order1_sell, &price1_lt_price2, fabric)
}
