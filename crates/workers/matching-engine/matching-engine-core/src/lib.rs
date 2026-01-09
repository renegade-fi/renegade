//! Core matching engine logic

use std::ops::RangeInclusive;

use circuit_types::{Amount, fixed_point::FixedPoint};
use crypto::fields::scalar_to_u128;
use darkpool_types::{
    fee::{FeeRates, FeeTake},
    settlement_obligation::{MatchResult, SettlementObligation},
};
use types_account::account::order::Order;
use util::on_chain::get_protocol_fee;

pub mod order_book;

// ------------
// | Matching |
// ------------

/// Match two orders at a given price and return the result amount if a match
/// exists
///
/// Each party may specify a range of input amounts they are willing to trade.
/// Practically, this range is intersected with relayer bounds enforcing minimum
/// trade sizes.
///
/// The price here is specified in terms of the first party's output token /
/// first party's input token. I.e. it is in the same units as the first party's
/// min price.
pub fn match_orders(
    o1: &Order,
    o2: &Order,
    in_bounds1: RangeInclusive<Amount>,
    in_bounds2: RangeInclusive<Amount>,
    price: FixedPoint,
) -> Option<MatchResult> {
    // Same asset pair
    let mut valid_match = o1.pair().reverse() == o2.pair();

    // Validate that the ranges intersect
    let out_bounds1 = input_to_output_range(in_bounds1, price);
    let out_bounds = range_intersection(out_bounds1, in_bounds2);
    if out_bounds.is_empty() {
        return None;
    }

    // The match occurs at the maximum point in the two ranges
    // "Output" here is in terms of the first party's output token;
    // and similar for "input"
    let max_output = *out_bounds.end();
    let max_input = scalar_to_u128(&price.floor_div_int(max_output));

    // Validate that the match amounts fall in the bounds for each order
    valid_match = valid_match && o1.validate_match_price(max_input, max_output);
    valid_match = valid_match && o2.validate_match_price(max_output, max_input); // swapped order
    if !valid_match {
        return None;
    }

    // Create the settlement obligations
    let obligation1 = SettlementObligation {
        input_token: o1.input_token(),
        output_token: o1.output_token(),
        amount_in: max_input,
        amount_out: max_output,
    };
    let obligation2 = SettlementObligation {
        input_token: o2.input_token(),
        output_token: o2.output_token(),
        amount_in: max_output,
        amount_out: max_input,
    };

    Some(MatchResult::new(obligation1, obligation2))
}

// --- Matching Helpers --- //

/// Convert an input range to an output range at the given price
///
/// The price is assumed to be in units of out_token / in_token.
fn input_to_output_range(
    input_range: RangeInclusive<Amount>,
    price: FixedPoint,
) -> RangeInclusive<Amount> {
    let out_start = scalar_to_u128(&price.floor_mul_int(*input_range.start()));
    let out_end = scalar_to_u128(&price.floor_mul_int(*input_range.end()));
    out_start..=out_end
}

/// Get the intersection of two ranges
fn range_intersection(
    range1: RangeInclusive<Amount>,
    range2: RangeInclusive<Amount>,
) -> RangeInclusive<Amount> {
    let start = Amount::max(*range1.start(), *range2.start());
    let end = Amount::min(*range1.end(), *range2.end());
    start..=end
}

// --------------
// | Settlement |
// --------------

/// Compute the fee obligations for a match
pub fn compute_fee_obligation(
    relayer_fee: FixedPoint,
    obligation: &SettlementObligation,
) -> FeeTake {
    let protocol_fee = get_protocol_fee();
    let rates = FeeRates::new(relayer_fee, protocol_fee);
    compute_fee_obligation_with_protocol_fee(rates, obligation)
}

/// Compute the fee obligation with a given protocol fee
pub fn compute_fee_obligation_with_protocol_fee(
    rates: FeeRates,
    obligation: &SettlementObligation,
) -> FeeTake {
    rates.compute_fee_take(obligation.amount_in)
}

#[cfg(test)]
mod tests {
    use std::ops::RangeInclusive;

    use alloy_primitives::Address;
    use circuit_types::{Amount, fixed_point::FixedPoint};
    use darkpool_types::{
        fuzzing::{BOUNDED_MAX_AMT, random_address, random_price},
        intent::Intent,
    };
    use rand::{Rng, thread_rng};
    use types_account::account::order::{Order, OrderMetadata};

    use crate::match_orders;

    // -----------
    // | Helpers |
    // -----------

    /// Generate a random order with the given tokens and min price
    fn random_order_with_tokens(
        in_token: Address,
        out_token: Address,
        min_price: FixedPoint,
    ) -> Order {
        let mut rng = thread_rng();
        let intent = Intent {
            in_token,
            out_token,
            owner: random_address(),
            min_price,
            amount_in: rng.gen_range(1..BOUNDED_MAX_AMT),
        };
        Order::new(intent, OrderMetadata::default())
    }

    /// Generate a counterparty order with reversed tokens
    fn counterparty_order(order: &Order, min_price: FixedPoint) -> Order {
        let mut rng = thread_rng();
        let intent = Intent {
            in_token: order.output_token(),
            out_token: order.input_token(),
            owner: random_address(),
            min_price,
            amount_in: rng.gen_range(1..BOUNDED_MAX_AMT),
        };
        Order::new(intent, OrderMetadata::default())
    }

    /// Generate random input bounds (inclusive)
    fn random_bounds() -> RangeInclusive<Amount> {
        let mut rng = thread_rng();
        let low = rng.gen_range(1..BOUNDED_MAX_AMT / 2);
        let high = rng.gen_range(low..BOUNDED_MAX_AMT);
        low..=high
    }

    // ---------------
    // | Match Tests |
    // ---------------

    /// Test valid matches between two orders with compatible bounds
    #[test]
    fn test_valid_match_fuzz() {
        let mut rng = thread_rng();

        // Create match data
        let token_a = random_address();
        let token_b = random_address();
        let price = random_price();

        // Party 1 trades token_a for token_b
        // Their min_price is in units of out_token/in_token = token_b/token_a
        // Set their min price below the match price so the match is valid
        let min_price1 = FixedPoint::from_f64_round_down(price.to_f64() * 0.8);
        let order1 = random_order_with_tokens(token_a, token_b, min_price1);

        // Party 2 wants to trade token_b for token_a (reversed)
        // Their min_price is in units of out_token/in_token = token_a/token_b
        // This is the inverse of party 1's price
        let inverse_price = 1.0 / price.to_f64();
        let min_price2 = FixedPoint::from_f64_round_down(inverse_price * 0.8);
        let order2 = counterparty_order(&order1, min_price2);

        // Generate overlapping bounds
        let shared_low = rng.gen_range(1..BOUNDED_MAX_AMT / 4);
        let shared_high = rng.gen_range(shared_low * 2..BOUNDED_MAX_AMT / 2);
        let bounds1 = shared_low..=shared_high;

        // Bounds2 needs to overlap with the output range of bounds1 at the given price
        // Output range of bounds1 = price * bounds1
        let out_low = (price.to_f64() * shared_low as f64) as Amount;
        let out_high = (price.to_f64() * shared_high as f64) as Amount;
        // Ensure bounds2 overlaps with the output range
        let bounds2 = out_low..=out_high.saturating_add(BOUNDED_MAX_AMT / 4);

        let match_result = match_orders(&order1, &order2, bounds1, bounds2, price)
            .expect("Should get a match when bounds overlap and prices are valid");

        // Verify the obligations are consistent
        let ob1 = match_result.party0_obligation();
        let ob2 = match_result.party1_obligation();

        // Party 1's output should equal party 2's input
        assert_eq!(ob1.amount_out, ob2.amount_in);
        // Party 1's input should equal party 2's output
        assert_eq!(ob1.amount_in, ob2.amount_out);

        // Tokens should be correctly assigned
        assert_eq!(ob1.input_token, token_a);
        assert_eq!(ob1.output_token, token_b);
        assert_eq!(ob2.input_token, token_b);
        assert_eq!(ob2.output_token, token_a);
    }

    /// Test that mismatched token pairs result in no match
    #[test]
    fn test_mismatched_pairs() {
        let token_a = random_address();
        let token_b = random_address();
        let token_c = random_address();

        let price = random_price();
        let min_price = FixedPoint::from_f64_round_down(price.to_f64() * 0.5);

        // Order1: token_a -> token_b
        let order1 = random_order_with_tokens(token_a, token_b, min_price);
        // Order2: token_a -> token_c
        let order2 = random_order_with_tokens(token_a, token_c, min_price);

        let bounds1 = random_bounds();
        let bounds2 = random_bounds();

        let result = match_orders(&order1, &order2, bounds1, bounds2, price);
        assert!(result.is_none(), "Mismatched pairs should not match");
    }

    /// Test that non-overlapping bounds result in no match
    #[test]
    fn test_non_overlapping_bounds() {
        let token_a = random_address();
        let token_b = random_address();

        let price = FixedPoint::from_f64_round_down(1.0); // Use price of 1 for simplicity
        let min_price = FixedPoint::from_f64_round_down(0.5);

        let order1 = random_order_with_tokens(token_a, token_b, min_price);
        let order2 = counterparty_order(&order1, min_price);

        // Create non-overlapping bounds
        // bounds1 output range: [100, 200] (at price 1.0)
        let bounds1 = 100..=200;
        // bounds2: [300, 400] - doesn't overlap with [100, 200]
        let bounds2 = 300..=400;

        let result = match_orders(&order1, &order2, bounds1, bounds2, price);
        assert!(result.is_none(), "Non-overlapping bounds should not match");
    }

    /// Test that a price below the first party's min price results in no match
    #[test]
    fn test_price_below_party1_min() {
        let token_a = random_address();
        let token_b = random_address();

        // Set a high min price for party 1
        let min_price1 = FixedPoint::from_f64_round_down(10.0);
        let order1 = random_order_with_tokens(token_a, token_b, min_price1);

        // Party 2 with low min price
        let min_price2 = FixedPoint::from_f64_round_down(0.01);
        let order2 = counterparty_order(&order1, min_price2);

        // Use a price below party 1's min price
        let price = FixedPoint::from_f64_round_down(5.0);

        let bounds1 = 100..=1000;
        let bounds2 = 100..=1000;

        let result = match_orders(&order1, &order2, bounds1, bounds2, price);
        assert!(result.is_none(), "Price below party1's min should not match");
    }

    /// Test that a price below the second party's min price results in no match
    #[test]
    fn test_price_below_party2_min() {
        let token_a = random_address();
        let token_b = random_address();

        // Party 1 with low min price
        let min_price1 = FixedPoint::from_f64_round_down(0.01);
        let order1 = random_order_with_tokens(token_a, token_b, min_price1);

        // Set a high min price for party 2 (in terms of token_a/token_b)
        // If match price is 10 (token_b/token_a), party2 sees inverse = 0.1
        // Set party2's min to 0.5 so the match fails
        let min_price2 = FixedPoint::from_f64_round_down(0.5);
        let order2 = counterparty_order(&order1, min_price2);

        // Match price of 10 means party2 gets 0.1 token_a per token_b
        // But party2 wants at least 0.5 token_a per token_b
        let price = FixedPoint::from_f64_round_down(10.0);

        let bounds1 = 100..=1000;
        let bounds2 = 100..=10000;

        let result = match_orders(&order1, &order2, bounds1, bounds2, price);
        assert!(result.is_none(), "Price below party2's min should not match");
    }

    /// Test that empty bounds result in no match
    #[test]
    fn test_empty_bounds() {
        let token_a = random_address();
        let token_b = random_address();

        let price = random_price();
        let min_price = FixedPoint::from_f64_round_down(price.to_f64() * 0.5);

        let order1 = random_order_with_tokens(token_a, token_b, min_price);
        let order2 = counterparty_order(&order1, min_price);

        // Empty bounds (start > end makes an empty inclusive range)
        #[allow(clippy::reversed_empty_ranges)]
        let empty_bounds: RangeInclusive<Amount> = 100..=99;
        let valid_bounds = random_bounds();

        let result1 =
            match_orders(&order1, &order2, empty_bounds.clone(), valid_bounds.clone(), price);
        assert!(result1.is_none(), "Empty bounds1 should not match");

        let result2 = match_orders(&order1, &order2, valid_bounds, empty_bounds, price);
        assert!(result2.is_none(), "Empty bounds2 should not match");
    }

    /// Test that the match amounts are at the maximum of the intersection
    #[test]
    fn test_match_amounts_at_maximum() {
        // Use deterministic values to verify the maximum is selected
        let token_a = random_address();
        let token_b = random_address();

        // Price of 1.0 for simplicity
        let price = FixedPoint::from_f64_round_down(1.0);
        let min_price = FixedPoint::from_f64_round_down(0.5);

        let order1 = random_order_with_tokens(token_a, token_b, min_price);
        let order2 = counterparty_order(&order1, min_price);

        // bounds1: [100, 500] -> output range at price 1.0: [100, 500]
        // bounds2: [200, 400]
        // Intersection: [200, 400]
        // The matching engine uses the inclusive upper bound (400) as the max output
        let bounds1 = 100..=500;
        let bounds2 = 200..=400;

        let result = match_orders(&order1, &order2, bounds1, bounds2, price)
            .expect("Should get a match when bounds overlap and prices are valid");
        let ob1 = result.party0_obligation();
        // The output amount should be at the inclusive end of the intersection
        assert_eq!(ob1.amount_out, 400, "Match should occur at maximum of intersection");
    }

    /// Test orders with the same direction (not reversed pairs) don't match
    #[test]
    fn test_same_direction_orders() {
        let token_a = random_address();
        let token_b = random_address();

        let price = random_price();
        let min_price = FixedPoint::from_f64_round_down(price.to_f64() * 0.5);

        // Both orders want to trade token_a -> token_b
        let order1 = random_order_with_tokens(token_a, token_b, min_price);
        let order2 = random_order_with_tokens(token_a, token_b, min_price);

        let bounds1 = random_bounds();
        let bounds2 = random_bounds();

        let result = match_orders(&order1, &order2, bounds1, bounds2, price);
        assert!(result.is_none(), "Same direction orders should not match");
    }
}
