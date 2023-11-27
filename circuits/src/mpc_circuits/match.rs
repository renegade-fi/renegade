//! Groups logic related to the match computation circuit

use circuit_types::{
    fixed_point::AuthenticatedFixedPoint, order::AuthenticatedOrder,
    r#match::AuthenticatedMatchResult, Fabric, AMOUNT_BITS,
};
use constants::{AuthenticatedScalar, Scalar};

use crate::mpc_gadgets::{comparators::min, fixed_point::FixedPointMpcGadget};

/// Executes a match computation that returns matches from a given order
/// intersection
///
/// We do not need to take in both orders directly, we instead take in the
/// advertised volume, which may be less than the order amount if the balances
/// in the wallet do not fully capitalize the order. The validity of these
/// amounts is constrained to be correct in the `VALID MATCH MPC` proof
///
/// We do not check whether the orders are valid and overlapping, this is left
/// to the `VALID MATCH MPC` circuit, which both parties verify before opening
/// the match result. So, if the match result is invalid, the orders don't
/// overlap, etc; the result will never be opened, and the information never
/// leaked. Therefore, we do not need to zero out any values in the circuit.
pub fn compute_match(
    party0_order: &AuthenticatedOrder,
    amount1: &AuthenticatedScalar,
    amount2: &AuthenticatedScalar,
    price: &AuthenticatedFixedPoint,
    fabric: &Fabric,
) -> AuthenticatedMatchResult {
    // Compute the amount and execution price that will be swapped if the orders
    // match
    let (min_index, min_base_amount) = min::<AMOUNT_BITS>(amount1, amount2, fabric);

    // The maximum of the two amounts minus the minimum of the two amounts
    let max_minus_min_amount = amount1 + amount2 - Scalar::from(2u64) * &min_base_amount;

    // The amount of quote token exchanged
    // Round down to the nearest integer value
    let quote_exchanged_fp = min_base_amount.clone() * price;
    let quote_exchanged = FixedPointMpcGadget::as_integer(&quote_exchanged_fp, fabric);

    // Zero out the orders if any of the initial checks failed
    AuthenticatedMatchResult {
        quote_mint: party0_order.quote_mint.clone(),
        base_mint: party0_order.base_mint.clone(),
        quote_amount: quote_exchanged,
        base_amount: min_base_amount,
        direction: party0_order.side.clone(),
        max_minus_min_amount,
        min_amount_order_index: min_index.into(),
    }
}

#[cfg(test)]
mod test {
    use ark_mpc::{PARTY0, PARTY1};
    use circuit_types::traits::{MpcBaseType, MpcType};

    use test_helpers::mpc_network::execute_mock_mpc;

    use crate::{mpc_circuits::r#match::compute_match, test_helpers::random_orders_and_match};

    /// Tests the match computation circuit
    #[tokio::test]
    async fn test_match_valid() {
        let (o1, o2, price, expected) = random_orders_and_match();

        let (res, _) = execute_mock_mpc(move |fabric| {
            let o1 = o1.clone();
            let o2 = o2.clone();

            async move {
                let o1_shared = o1.allocate(PARTY0, &fabric);
                let o2_shared = o2.allocate(PARTY1, &fabric);
                let price = price.allocate(PARTY0, &fabric);

                let res = compute_match(
                    &o1_shared,
                    &o1_shared.amount,
                    &o2_shared.amount,
                    &price,
                    &fabric,
                );

                res.open_and_authenticate().await.unwrap()
            }
        })
        .await;

        assert_eq!(res, expected);
    }
}
