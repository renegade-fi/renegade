//! Groups logic related to the match computation circuit

use circuit_types::{
    fixed_point::{AuthenticatedFixedPoint, FixedPoint},
    order::AuthenticatedLinkableOrder,
    r#match::AuthenticatedMatchResult,
    AMOUNT_BITS,
};
use constants::PROTOCOL_FEE;
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
    let quote_exchanged = FixedPointMpcGadget::as_integer(quote_exchanged_fp.clone(), fabric);

    // We compute the protocol fee directly on the `quote_exchanged_fp` before it is rounded to an
    // integer. This avoids data dependence on the rounding operation, which has round depth logarithmic
    // in the field size. Computing the protocol fee based on the input to the rounding operation lets us
    // schedule these operations in parallel
    let protocol_quote_fee_amount = compute_protocol_fee(&quote_exchanged_fp, fabric);
    let protocol_base_fee_amount = compute_protocol_fee(
        &AuthenticatedFixedPoint::from_integer(&min_base_amount),
        fabric,
    );

    // Zero out the orders if any of the initial checks failed
    AuthenticatedMatchResult {
        quote_mint: order1.quote_mint.value().clone(),
        base_mint: order1.base_mint.value().clone(),
        quote_amount: quote_exchanged,
        base_amount: min_base_amount,
        direction: order1.side.value().clone(),
        protocol_quote_fee_amount,
        protocol_base_fee_amount,
        max_minus_min_amount,
        min_amount_order_index: min_index,
    }
}

/// Compute the protocol fee for a given match result
pub fn compute_protocol_fee(
    token_amount: &AuthenticatedFixedPoint,
    fabric: &MpcFabric,
) -> AuthenticatedScalarResult {
    // Compute the protocol fee
    let protocol_fee = FixedPoint::from_f64_round_down(PROTOCOL_FEE);
    let protocol_fee_amount = token_amount * &protocol_fee;

    // Round down to the nearest integral value
    FixedPointMpcGadget::as_integer(protocol_fee_amount, fabric)
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod tests {
    use std::cmp;

    use circuit_types::{
        fixed_point::FixedPoint,
        order::{Order, OrderSide},
        r#match::MatchResult,
        traits::{LinkableBaseType, MpcBaseType, MpcType},
    };
    use constants::PROTOCOL_FEE;
    use lazy_static::lazy_static;
    use mpc_stark::{algebra::scalar::Scalar, PARTY0, PARTY1};
    use num_bigint::BigUint;
    use renegade_crypto::fields::scalar_to_u64;
    use test_helpers::mpc_network::execute_mock_mpc;

    use crate::mpc_circuits::r#match::compute_match;

    // -----------
    // | Helpers |
    // -----------

    lazy_static! {
        /// A dummy first order used for testing
        static ref ORDER1: Order = Order {
            quote_mint: BigUint::from(1u8),
            base_mint: BigUint::from(2u8),
            side: OrderSide::Buy,
            amount: 100_000,
            worst_case_price: 15f32.into(),
            timestamp: 0,
        };
        /// A dummy second order that matches with the first
        static ref ORDER2: Order = Order {
            side: OrderSide::Sell,
            amount: 50_000,
            worst_case_price: 4f32.into(),
            ..ORDER1.clone()
        };
        /// A dummy execution price
        static ref PRICE: FixedPoint = FixedPoint::from_integer(10);
    }

    /// Execute a match on the dummy values above and return the match result
    async fn execute_match_on_orders() -> MatchResult {
        let (match_res, _) = execute_mock_mpc(|fabric| async move {
            // Allocate dummy orders and compute a match
            let o1 = ORDER1.to_linkable().allocate(PARTY0, &fabric);
            let o2 = ORDER2.to_linkable().allocate(PARTY1, &fabric);

            let amount1 = o1.amount.value().clone();
            let amount2 = o2.amount.value().clone();

            let price = PRICE.clone().allocate(PARTY0, &fabric);

            let match_res = compute_match(&o1, &o2, &amount1, &amount2, &price, &fabric);
            match_res.open().await.unwrap()
        })
        .await;

        match_res
    }

    /// Compute the expected protocol fee on a given match amount
    fn expected_protocol_fee(amount: u64) -> u64 {
        let fee = FixedPoint::from_f64_round_down(PROTOCOL_FEE);
        let fee_take = fee * Scalar::from(amount);

        scalar_to_u64(&fee_take.floor())
    }

    // ---------
    // | Tests |
    // ---------

    /// Tests that the match computation correctly computes the volumes matched
    #[tokio::test]
    async fn test_match_volumes() {
        // Get the match result
        let res = execute_match_on_orders().await;

        // Check the volumes
        let expected_base = cmp::min(ORDER1.amount, ORDER2.amount);
        let expected_quote = (*PRICE * Scalar::from(expected_base)).floor();

        assert_eq!(res.quote_amount, scalar_to_u64(&expected_quote));
        assert_eq!(res.base_amount, expected_base);
    }

    /// Tests that the match computation correctly computes the protocol fee
    #[tokio::test]
    async fn test_match_protocol_fee() {
        // Get the match result
        let res = execute_match_on_orders().await;

        // Check the protocol fee amount
        let expected_quote_fee = expected_protocol_fee(res.quote_amount);
        let expected_base_fee = expected_protocol_fee(res.base_amount);

        assert_eq!(expected_quote_fee, res.protocol_quote_fee_amount);
        assert_eq!(expected_base_fee, res.protocol_base_fee_amount);
    }
}
