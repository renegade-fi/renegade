//! Helpers for the matching engine

use circuit_types::{
    balance::Balance,
    fixed_point::{FixedPoint, PROTOCOL_FEE_FP},
    order::{Order, OrderSide},
    r#match::{FeeTake, MatchResult, OrderSettlementIndices},
    wallet::WalletShare,
    Amount,
};
use constants::Scalar;
use renegade_crypto::fields::scalar_to_u128;

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
    max1: Amount,
    max2: Amount,
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
    let min_base_amount = Amount::min(max1, max2);
    valid_match = valid_match && min_base_amount > 0;

    if !valid_match {
        return None;
    }

    // Compute the auth data for the match
    let quote_amount = price * Scalar::from(min_base_amount);
    let quote_amount = scalar_to_u128(&quote_amount.floor());

    Some(MatchResult {
        base_mint: o1.base_mint.clone(),
        quote_mint: o1.quote_mint.clone(),
        base_amount: min_base_amount,
        quote_amount,
        direction: matches!(o1.side, OrderSide::Sell),
        min_amount_order_index: max1 > max2,
    })
}

/// Compute the maximum matchable amount for an order and balance
pub fn compute_max_amount(price: &FixedPoint, order: &Order, balance: &Balance) -> Amount {
    match order.side {
        // Buy the base, the max amount is possibly limited by the quote
        // balance
        OrderSide::Buy => {
            let price_f64 = price.to_f64();
            let balance_limit = (balance.amount as f64 / price_f64).floor() as u128;
            u128::min(order.amount, balance_limit)
        },
        // Buy the quote, sell the base, the maximum amount is directly limited
        // by the balance
        OrderSide::Sell => u128::min(order.amount, balance.amount),
    }
}

// --------------
// | Settlement |
// --------------

/// Apply a match to two wallet secret shares
pub fn settle_match_into_wallets<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
    wallet0_share: &mut WalletShare<MAX_BALANCES, MAX_ORDERS>,
    wallet1_share: &mut WalletShare<MAX_BALANCES, MAX_ORDERS>,
    party0_fees: FeeTake,
    party1_fees: FeeTake,
    party0_indices: OrderSettlementIndices,
    party1_indices: OrderSettlementIndices,
    match_res: &MatchResult,
) where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    let direction = OrderSide::from(match_res.direction);
    apply_match_to_shares(wallet0_share, &party0_indices, party0_fees, match_res, direction);
    apply_match_to_shares(
        wallet1_share,
        &party1_indices,
        party1_fees,
        match_res,
        direction.opposite(),
    );
}

/// Applies a match to the shares of a wallet
///
/// Returns a new wallet share with the match applied
pub fn apply_match_to_shares<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
    shares: &mut WalletShare<MAX_BALANCES, MAX_ORDERS>,
    indices: &OrderSettlementIndices,
    fees: FeeTake,
    match_res: &MatchResult,
    side: OrderSide,
) where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    let (_, send_amt) = match_res.send_mint_amount(side);
    let (_, recv_amt) = match_res.receive_mint_amount(side);

    // Update the matched order
    shares.orders[indices.order].amount -= Scalar::from(match_res.base_amount);
    // Update the send balance
    shares.balances[indices.balance_send].amount -= Scalar::from(send_amt);

    // Update the receive balance including fees
    let trader_net = recv_amt - fees.total();
    shares.balances[indices.balance_receive].amount += Scalar::from(trader_net);
    shares.balances[indices.balance_receive].relayer_fee_balance += Scalar::from(fees.relayer_fee);
    shares.balances[indices.balance_receive].protocol_fee_balance +=
        Scalar::from(fees.protocol_fee);
}

/// Compute the fee obligations for a match
pub fn compute_fee_obligation(
    relayer_fee: FixedPoint,
    side: OrderSide,
    match_res: &MatchResult,
) -> FeeTake {
    let (_mint, receive_amount) = match_res.receive_mint_amount(side);
    let receive_amount = Scalar::from(receive_amount);

    let relayer_take = (relayer_fee * receive_amount).floor();
    let protocol_take = (*PROTOCOL_FEE_FP * receive_amount).floor();

    FeeTake {
        relayer_fee: scalar_to_u128(&relayer_take),
        protocol_fee: scalar_to_u128(&protocol_take),
    }
}

#[cfg(test)]
mod tests {
    use std::iter;

    use crate::matching_engine::compute_fee_obligation;

    use super::{apply_match_to_shares, match_orders};
    use circuit_types::{
        balance::Balance,
        fixed_point::FixedPoint,
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
        };

        /// The first dummy balance used in a valid match
        static ref BALANCE1: Balance = Balance {
            mint: 2u64.into(),
            amount: 500u128,
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
        };

        /// The second dummy balance used in a valid match
        static ref BALANCE2: Balance = Balance {
            mint: 1u64.into(),
            amount: 100u128,
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

    /// Generate a random relayer fee
    ///
    /// Generates in the range of 1 bp to 100 bp
    fn random_relayer_fee() -> FixedPoint {
        let mut rng = thread_rng();
        let fee: f64 = rng.gen_range(0.0001..0.01);

        FixedPoint::from_f64_round_down(fee)
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
        balance1.amount = (midpoint_price * 10.) as u128;

        let res =
            match_orders(&order1, &order2, &balance1, &balance2, midpoint_price.into()).unwrap();

        assert_eq!(res.base_mint, 1u64.into());
        assert_eq!(res.quote_mint, 2u64.into());
        assert_eq!(res.base_amount, 10);
        assert_eq!(res.quote_amount, 70 /* midpoint_price * base_amount */);
        assert_eq!(res.direction as u8, 0);
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
        balance2.amount = 10u128;

        let res =
            match_orders(&order1, &order2, &balance1, &balance2, midpoint_price.into()).unwrap();

        assert_eq!(res.base_mint, 1u64.into());
        assert_eq!(res.quote_mint, 2u64.into());
        assert_eq!(res.base_amount, 10);
        assert_eq!(res.quote_amount, 70 /* midpoint_price * base_amount */);
        assert_eq!(res.direction as u8, 0);
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
    #[allow(non_snake_case)]
    fn test_settle_match__buy_side() {
        let side = OrderSide::Buy;
        let match_res = random_match_result();
        let indices = random_settlement_indices();
        let original_shares = random_wallet_share();

        let relayer_fee = random_relayer_fee();
        let fees = compute_fee_obligation(relayer_fee, side, &match_res);

        let mut new_shares = original_shares.clone();
        apply_match_to_shares(&mut new_shares, &indices, fees, &match_res, side);

        let expected_order_amt = original_shares.orders[indices.order as usize].amount
            - Scalar::from(match_res.base_amount);
        let expected_quote_amt = original_shares.balances[indices.balance_send as usize].amount
            - Scalar::from(match_res.quote_amount);

        let net_recv = match_res.base_amount - fees.total();
        let expected_base_amt = original_shares.balances[indices.balance_receive as usize].amount
            + Scalar::from(net_recv);
        let expected_base_relayer_fee = original_shares.balances[indices.balance_receive as usize]
            .relayer_fee_balance
            + Scalar::from(fees.relayer_fee);
        let expected_base_protocol_fee = original_shares.balances[indices.balance_receive as usize]
            .protocol_fee_balance
            + Scalar::from(fees.protocol_fee);

        assert_eq!(new_shares.balances[indices.balance_send as usize].amount, expected_quote_amt);
        assert_eq!(new_shares.balances[indices.balance_receive as usize].amount, expected_base_amt);
        assert_eq!(
            new_shares.balances[indices.balance_receive as usize].relayer_fee_balance,
            expected_base_relayer_fee
        );
        assert_eq!(
            new_shares.balances[indices.balance_receive as usize].protocol_fee_balance,
            expected_base_protocol_fee
        );
        assert_eq!(new_shares.orders[indices.order as usize].amount, expected_order_amt);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_settle_match__sell_side() {
        let side = OrderSide::Sell;
        let match_res = random_match_result();
        let indices = random_settlement_indices();
        let original_shares = random_wallet_share();

        let relayer_fee = random_relayer_fee();
        let fees = compute_fee_obligation(relayer_fee, side, &match_res);

        let mut new_shares = original_shares.clone();
        apply_match_to_shares(&mut new_shares, &indices, fees, &match_res, side);

        let expected_order_amt = original_shares.orders[indices.order as usize].amount
            - Scalar::from(match_res.base_amount);
        let expected_base_amt = original_shares.balances[indices.balance_send as usize].amount
            - Scalar::from(match_res.base_amount);

        let net_recv = match_res.quote_amount - fees.total();
        let expected_quote_amt = original_shares.balances[indices.balance_receive as usize].amount
            + Scalar::from(net_recv);
        let expected_base_relayer_fee = original_shares.balances[indices.balance_receive as usize]
            .relayer_fee_balance
            + Scalar::from(fees.relayer_fee);
        let expected_base_protocol_fee = original_shares.balances[indices.balance_receive as usize]
            .protocol_fee_balance
            + Scalar::from(fees.protocol_fee);

        assert_eq!(new_shares.balances[indices.balance_send as usize].amount, expected_base_amt);
        assert_eq!(
            new_shares.balances[indices.balance_receive as usize].amount,
            expected_quote_amt
        );
        assert_eq!(
            new_shares.balances[indices.balance_receive as usize].relayer_fee_balance,
            expected_base_relayer_fee
        );
        assert_eq!(
            new_shares.balances[indices.balance_receive as usize].protocol_fee_balance,
            expected_base_protocol_fee
        );
        assert_eq!(new_shares.orders[indices.order as usize].amount, expected_order_amt);
    }
}
