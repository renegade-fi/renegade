//! Groups logic related to the match computation circuit

use circuit_types::{
    fixed_point::AuthenticatedFixedPoint, order::AuthenticatedLinkableOrder,
    r#match::AuthenticatedMatchResult, AMOUNT_BITS,
};
use mpc_stark::{
    algebra::{authenticated_scalar::AuthenticatedScalarResult, scalar::Scalar},
    MpcFabric,
};

use crate::mpc_gadgets::{comparators::min, fixed_point::FixedPointMpcGadget};

/// Executes a match computation that returns matches from a given order intersection
///
/// If no match is found, the values are opened to a zero'd list
///
/// We do not check whether the orders are valid and overlapping, this is left to the
/// `VALID MATCH MPC` circuit, which both parties verify before opening the match result.
/// So, if the match result is invalid, the orders don't overlap, etc; the result will
/// never be opened, and the information never leaked. Therefore, we do not need to zero
/// out any values in the circuit.
pub fn compute_match(
    order1: &AuthenticatedLinkableOrder,
    order2: &AuthenticatedLinkableOrder,
    amount1: &AuthenticatedScalarResult,
    amount2: &AuthenticatedScalarResult,
    price: &AuthenticatedFixedPoint,
    fabric: &MpcFabric,
) -> AuthenticatedMatchResult {
    // Compute the amount and execution price that will be swapped if the orders match
    let (min_index, min_base_amount) = min::<AMOUNT_BITS>(amount1, amount2, fabric);

    // The maximum of the two amounts minus the minimum of the two amounts
    let max_minus_min_amount =
        order1.amount.value() + order2.amount.value() - Scalar::from(2u64) * &min_base_amount;

    // The amount of quote token exchanged
    // Round down to the nearest integer value
    let quote_exchanged_fp = min_base_amount.clone() * price;
    let quote_exchanged = FixedPointMpcGadget::as_integer(quote_exchanged_fp, fabric);

    // Zero out the orders if any of the initial checks failed
    AuthenticatedMatchResult {
        quote_mint: order1.quote_mint.value().clone(),
        base_mint: order1.base_mint.value().clone(),
        quote_amount: quote_exchanged,
        base_amount: min_base_amount,
        direction: order1.side.value().clone(),
        max_minus_min_amount,
        min_amount_order_index: min_index,
    }
}
