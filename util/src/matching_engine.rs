//! Helpers for the matching engine

use circuit_types::{
    balance::Balance,
    fixed_point::FixedPoint,
    order::{Order, OrderSide},
    r#match::{MatchResult, OrderSettlementIndices},
    wallet::WalletShare,
};
use constants::Scalar;
use renegade_crypto::fields::scalar_to_u64;

// ------------
// | Matching |
// ------------

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
pub fn compute_max_amount(price: &FixedPoint, order: &Order, balance: &Balance) -> u64 {
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

// --------------
// | Settlement |
// --------------

/// Apply a match to two wallet secret shares
pub fn settle_match_into_wallets<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
>(
    wallet0_share: &mut WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    wallet1_share: &mut WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    party0_indices: OrderSettlementIndices,
    party1_indices: OrderSettlementIndices,
    match_res: &MatchResult,
) where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    let direction = OrderSide::from(match_res.direction);
    apply_match_to_shares(wallet0_share, &party0_indices, match_res, direction);
    apply_match_to_shares(wallet1_share, &party1_indices, match_res, direction.opposite());
}

/// Applies a match to the shares of a wallet
///
/// Returns a new wallet share with the match applied
pub fn apply_match_to_shares<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
>(
    shares: &mut WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    indices: &OrderSettlementIndices,
    match_res: &MatchResult,
    side: OrderSide,
) where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    let (send_amt, recv_amt) = match side {
        // Buy side; send quote, receive base
        OrderSide::Buy => (match_res.quote_amount, match_res.base_amount),
        // Sell side; send base, receive quote
        OrderSide::Sell => (match_res.base_amount, match_res.quote_amount),
    };

    shares.balances[indices.balance_send].amount -= Scalar::from(send_amt);
    shares.balances[indices.balance_receive].amount += Scalar::from(recv_amt);
    shares.orders[indices.order].amount -= Scalar::from(match_res.base_amount);
}

#[cfg(test)]
mod tests {
    use std::iter;

    use super::{apply_match_to_shares, match_orders};
    use circuit_types::{
        balance::Balance,
        order::{Order, OrderSide},
        r#match::{MatchResult, OrderSettlementIndices},
        traits::BaseType,
        SizedWalletShare,
    };
    use constants::{Scalar, MAX_BALANCES, MAX_ORDERS};
    use lazy_static::lazy_static;
    use num_bigint::RandBigInt;
    use rand::{distributions::uniform::SampleRange, thread_rng, Rng};

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
            relayer_fee_balance: 0,
            protocol_fee_balance: 0,
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
            relayer_fee_balance: 0,
            protocol_fee_balance: 0,
        };
    }

    // -----------
    // | Helpers |
    // -----------

    /// Get a random match result
    fn random_match_result() -> MatchResult {
        let mut rng = thread_rng();

        MatchResult {
            base_mint: rng.gen_biguint(100 /* bits */),
            quote_mint: rng.gen_biguint(100 /* bits */),
            base_amount: rng.gen(),
            quote_amount: rng.gen(),
            direction: rng.gen(),
            max_minus_min_amount: rng.gen(),
            min_amount_order_index: rng.gen(),
        }
    }

    /// Generate a set of random wallet share
    fn random_wallet_share() -> SizedWalletShare {
        let mut rng = thread_rng();
        let mut iter = iter::from_fn(|| Some(Scalar::random(&mut rng)));

        SizedWalletShare::from_scalars(&mut iter)
    }

    /// Generate a set of random settlement indices
    fn random_settlement_indices() -> OrderSettlementIndices {
        let mut rng = thread_rng();
        let send = (0..MAX_BALANCES).sample_single(&mut rng);

        let mut recv = (0..MAX_BALANCES).sample_single(&mut rng);
        while recv == send {
            recv = (0..MAX_BALANCES).sample_single(&mut rng);
        }

        OrderSettlementIndices {
            order: (0..MAX_ORDERS).sample_single(&mut rng),
            balance_send: send,
            balance_receive: recv,
        }
    }

    // ---------------
    // | Match Tests |
    // ---------------

    /// Test a valid match between two orders
    #[test]
    fn test_valid_match() {
        let order1 = ORDER1.clone();
        let balance1 = BALANCE1.clone();
        let order2 = ORDER2.clone();
        let balance2 = BALANCE2.clone();
        let midpoint_price = 7.;

        let res =
            match_orders(&order1, &order2, &balance1, &balance2, midpoint_price.into()).unwrap();

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

        let res =
            match_orders(&order1, &order2, &balance1, &balance2, midpoint_price.into()).unwrap();

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

        let res =
            match_orders(&order1, &order2, &balance1, &balance2, midpoint_price.into()).unwrap();

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

        let res = match_orders(&order1, &order2, &balance1, &balance2, midpoint_price.into());

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

        let res = match_orders(&order1, &order2, &balance1, &balance2, midpoint_price.into());

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

        let res = match_orders(&order1, &order2, &balance1, &balance2, midpoint_price.into());

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

        let res = match_orders(&order1, &order2, &balance1, &balance2, midpoint_price.into());

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

        let res = match_orders(&order1, &order2, &balance1, &balance2, midpoint_price.into());

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

        let res = match_orders(&order1, &order2, &balance1, &balance2, midpoint_price.into());

        assert!(res.is_none());
    }

    // --------------------
    // | Settlement Tests |
    // --------------------

    /// Tests settling a match into two wallet shares
    #[test]
    fn test_settle_match() {
        // Buy side
        let match_res = random_match_result();
        let indices = random_settlement_indices();
        let original_shares = random_wallet_share();

        let mut new_shares = original_shares.clone();
        apply_match_to_shares(&mut new_shares, &indices, &match_res, OrderSide::Buy);

        let expected_order_amt = original_shares.orders[indices.order as usize].amount
            - Scalar::from(match_res.base_amount);
        let expected_quote_amt = original_shares.balances[indices.balance_send as usize].amount
            - Scalar::from(match_res.quote_amount);
        let expected_base_amt = original_shares.balances[indices.balance_receive as usize].amount
            + Scalar::from(match_res.base_amount);
        assert_eq!(new_shares.balances[indices.balance_send as usize].amount, expected_quote_amt);
        assert_eq!(new_shares.balances[indices.balance_receive as usize].amount, expected_base_amt);
        assert_eq!(new_shares.orders[indices.order as usize].amount, expected_order_amt);

        // Sell side
        let mut new_shares = original_shares.clone();
        apply_match_to_shares(&mut new_shares, &indices, &match_res, OrderSide::Sell);

        let expected_quote_amt = original_shares.balances[indices.balance_receive as usize].amount
            + Scalar::from(match_res.quote_amount);
        let expected_base_amt = original_shares.balances[indices.balance_send as usize].amount
            - Scalar::from(match_res.base_amount);
        assert_eq!(new_shares.balances[indices.balance_send as usize].amount, expected_base_amt);
        assert_eq!(
            new_shares.balances[indices.balance_receive as usize].amount,
            expected_quote_amt
        );
        assert_eq!(new_shares.orders[indices.order as usize].amount, expected_order_amt);
    }
}
