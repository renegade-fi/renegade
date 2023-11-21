//! Helpers for the matching engine

use circuit_types::{
    balance::Balance,
    fixed_point::FixedPoint,
    order::{Order, OrderSide},
    r#match::MatchResult,
};
use constants::Scalar;
use renegade_crypto::fields::scalar_to_u64;

/// Match two orders at a given price and return the result amount if a match
/// exists
///
/// The amounts passed in represent the maximum fill that the owner of each
/// order may commit to. This is determined by the balance in their wallet at
/// the time of the match
pub fn match_orders(
    o1: &Order,
    o2: &Order,
    b1: &Balance,
    b2: &Balance,
    price: FixedPoint,
) -> Option<MatchResult> {
    // Compute the amount matched by the engine
    let party0_max_amount = compute_max_amount(&price, o1, b1);
    let party1_max_amount = compute_max_amount(&price, o2, b2);

    match_orders_with_max_amount(o1, o2, party0_max_amount, party1_max_amount, price)
}

/// Match two orders with a given maximum amount for each side
///
/// Note that this method does not verify that the maximum subscribed amount for
/// each party is properly capitalized in the party's wallet. This should be
/// done by the caller.
///
/// These maximums are dependent upon the balance of each order's owner for
/// the token they trade. Optionally, a party in a match may voluntarily
/// subscribe to a maximum amount lower than what is permitted by their balance
pub fn match_orders_with_max_amount(
    o1: &Order,
    o2: &Order,
    max1: u64,
    max2: u64,
    price: FixedPoint,
) -> Option<MatchResult> {
    // Same asset pair
    let mut valid_match =
        o1.base_mint == o2.base_mint && o1.quote_mint == o2.quote_mint && o1.side != o2.side;

    // Validate that the midpoint price is acceptable for both orders
    valid_match = valid_match && o1.price_in_range(price) && o2.price_in_range(price);

    // Neither order is zero'd out
    // Orders are not removed when they are zero'd because a counterparty cannot
    // update shares to remove an order without revealing the volume of the
    // order. So zero'd orders may exist in the book until the user removes them
    valid_match = valid_match && !o1.is_zero() && !o2.is_zero();
    let min_base_amount = u64::min(max1, max2);
    valid_match = valid_match && min_base_amount > 0;

    if !valid_match {
        return None;
    }

    // Compute the auxiliary data for the match
    let quote_amount = price * Scalar::from(min_base_amount);
    let quote_amount = scalar_to_u64(&quote_amount.floor());
    let max_minus_min_amount = u64::max(max1, max2) - min_base_amount;

    Some(MatchResult {
        base_mint: o1.base_mint.clone(),
        quote_mint: o1.quote_mint.clone(),
        base_amount: min_base_amount,
        quote_amount,
        direction: matches!(o1.side, OrderSide::Sell),
        max_minus_min_amount,
        min_amount_order_index: max1 > max2,
    })
}

/// Compute the maximum matchable amount for an order and balance
fn compute_max_amount(price: &FixedPoint, order: &Order, balance: &Balance) -> u64 {
    match order.side {
        // Buy the base, the max amount is possibly limited by the quote
        // balance
        OrderSide::Buy => {
            let price_f64 = price.to_f64();
            let balance_limit = (balance.amount as f64 / price_f64).floor() as u64;
            u64::min(order.amount, balance_limit)
        },
        // Buy the quote, sell the base, the maximum amount is directly limited
        // by the balance
        OrderSide::Sell => u64::min(order.amount, balance.amount),
    }
}

#[cfg(test)]
mod tests {
    use super::match_orders;
    use circuit_types::{
        balance::Balance,
        order::{Order, OrderSide},
    };
    use lazy_static::lazy_static;

    // --------------
    // | Dummy Data |
    // --------------

    /// The worst case price for the buy side
    const BUY_SIDE_WORST_CASE_PRICE: f32 = 10.;
    /// The worst case price for the sell side
    const SELL_SIDE_WORST_CASE_PRICE: f32 = 5.;

    lazy_static! {
        /// The first dummy order used in a valid match
        static ref ORDER1: Order = Order {
            base_mint: 1u64.into(),
            quote_mint: 2u64.into(),
            side: OrderSide::Buy,
            amount: 50,
            worst_case_price: BUY_SIDE_WORST_CASE_PRICE.into(),
            timestamp: 0,
        };

        /// The first dummy balance used in a valid match
        static ref BALANCE1: Balance = Balance {
            mint: 2u64.into(),
            amount: 500u64,
        };

        /// The second dummy order used in a valid match
        static ref ORDER2: Order = Order {
            base_mint: 1u64.into(),
            quote_mint: 2u64.into(),
            side: OrderSide::Sell,
            amount: 100,
            worst_case_price: SELL_SIDE_WORST_CASE_PRICE.into(),
            timestamp: 0,
        };

        /// The second dummy balance used in a valid match
        static ref BALANCE2: Balance = Balance {
            mint: 1u64.into(),
            amount: 100u64,
        };
    }

    // ---------
    // | Tests |
    // ---------

    /// Test a valid match between two orders
    #[test]
    fn test_valid_match() {
        let order1 = ORDER1.clone();
        let balance1 = BALANCE1.clone();
        let order2 = ORDER2.clone();
        let balance2 = BALANCE2.clone();
        let midpoint_price = 7.;

        let res = match_orders(
            &order1,
            &order2,
            &balance1,
            &balance2,
            midpoint_price.into(),
        )
        .unwrap();

        assert_eq!(res.base_mint, 1u64.into());
        assert_eq!(res.quote_mint, 2u64.into());
        assert_eq!(res.base_amount, 50);
        assert_eq!(
            res.quote_amount,
            350 // midpoint_price * base_amount
        );
        assert_eq!(res.direction as u8, 0);
        assert_eq!(res.max_minus_min_amount, 50);
        assert_eq!(res.min_amount_order_index as u8, 0);
    }

    /// Test a valid match between two order where the buy side is
    /// undercapitalized
    #[test]
    fn test_valid_match_undercapitalized_buy() {
        let order1 = ORDER1.clone();
        let mut balance1 = BALANCE1.clone();
        let order2 = ORDER2.clone();
        let balance2 = BALANCE2.clone();
        let midpoint_price = 7.;

        // Can only buy 10 units of the base
        balance1.amount = (midpoint_price * 10.) as u64;

        let res = match_orders(
            &order1,
            &order2,
            &balance1,
            &balance2,
            midpoint_price.into(),
        )
        .unwrap();

        assert_eq!(res.base_mint, 1u64.into());
        assert_eq!(res.quote_mint, 2u64.into());
        assert_eq!(res.base_amount, 10);
        assert_eq!(res.quote_amount, 70 /* midpoint_price * base_amount */);
        assert_eq!(res.direction as u8, 0);
        assert_eq!(res.max_minus_min_amount, 90);
        assert_eq!(res.min_amount_order_index as u8, 0);
    }

    /// Test a valid match between two order where the sell side is
    /// undercapitalized
    #[test]
    fn test_valid_match_undercapitalized_sell() {
        let order1 = ORDER1.clone();
        let balance1 = BALANCE1.clone();
        let order2 = ORDER2.clone();
        let mut balance2 = BALANCE2.clone();
        let midpoint_price = 7.;

        // Can only sell 10 units of the base
        balance2.amount = 10u64;

        let res = match_orders(
            &order1,
            &order2,
            &balance1,
            &balance2,
            midpoint_price.into(),
        )
        .unwrap();

        assert_eq!(res.base_mint, 1u64.into());
        assert_eq!(res.quote_mint, 2u64.into());
        assert_eq!(res.base_amount, 10);
        assert_eq!(res.quote_amount, 70 /* midpoint_price * base_amount */);
        assert_eq!(res.direction as u8, 0);
        assert_eq!(res.max_minus_min_amount, 40);
        assert_eq!(res.min_amount_order_index as u8, 1);
    }

    /// Test mismatched base mints
    #[test]
    fn test_mismatched_base_mints() {
        let order1 = ORDER1.clone();
        let balance1 = BALANCE1.clone();
        let mut order2 = ORDER2.clone();
        let balance2 = BALANCE2.clone();

        order2.base_mint = 3u64.into();
        let midpoint_price = 7.;

        let res = match_orders(
            &order1,
            &order2,
            &balance1,
            &balance2,
            midpoint_price.into(),
        );

        assert!(res.is_none());
    }

    /// Test mismatched quote mints
    #[test]
    fn test_mismatched_quote_mints() {
        let order1 = ORDER1.clone();
        let balance1 = BALANCE1.clone();
        let mut order2 = ORDER2.clone();
        let balance2 = BALANCE2.clone();

        order2.quote_mint = 3u64.into();
        let midpoint_price = 7.;

        let res = match_orders(
            &order1,
            &order2,
            &balance1,
            &balance2,
            midpoint_price.into(),
        );

        assert!(res.is_none());
    }

    /// Test two orders on the same side of the book
    #[test]
    fn test_same_side() {
        let order1 = ORDER1.clone();
        let balance1 = BALANCE1.clone();
        let mut order2 = ORDER2.clone();
        let balance2 = BALANCE2.clone();

        order2.side = order1.side;
        let midpoint_price = 7.;

        let res = match_orders(
            &order1,
            &order2,
            &balance1,
            &balance2,
            midpoint_price.into(),
        );

        assert!(res.is_none());
    }

    /// Test a midpoint price out of the buy side range
    #[test]
    fn test_buy_price_out_of_range() {
        let order1 = ORDER1.clone();
        let balance1 = BALANCE1.clone();
        let order2 = ORDER2.clone();
        let balance2 = BALANCE2.clone();

        let midpoint_price = BUY_SIDE_WORST_CASE_PRICE + 1.;

        let res = match_orders(
            &order1,
            &order2,
            &balance1,
            &balance2,
            midpoint_price.into(),
        );

        assert!(res.is_none());
    }

    /// Test a midpoint price out of the sell side range
    #[test]
    fn test_sell_price_out_of_range() {
        let order1 = ORDER1.clone();
        let balance1 = BALANCE1.clone();
        let order2 = ORDER2.clone();
        let balance2 = BALANCE2.clone();

        let midpoint_price = SELL_SIDE_WORST_CASE_PRICE - 1.;

        let res = match_orders(
            &order1,
            &order2,
            &balance1,
            &balance2,
            midpoint_price.into(),
        );

        assert!(res.is_none());
    }

    /// Tests a balance of zero on one side
    #[test]
    fn test_zero_balance() {
        let order1 = ORDER1.clone();
        let balance1 = BALANCE1.clone();
        let order2 = ORDER2.clone();
        let mut balance2 = BALANCE2.clone();

        balance2.amount = 0;
        let midpoint_price = 7.;

        let res = match_orders(
            &order1,
            &order2,
            &balance1,
            &balance2,
            midpoint_price.into(),
        );

        assert!(res.is_none());
    }
}
