//! Helpers for matching orders

use circuit_types::{Amount, balance::Balance, fixed_point::FixedPoint, r#match::MatchResult};
use common::types::{
    price::{TimestampedPrice, TimestampedPriceFp},
    token::Token,
    wallet::{Order, OrderIdentifier},
};
use util::{err_str, matching_engine::match_orders_with_min_base_amount};

use crate::{error::HandshakeManagerError, manager::HandshakeExecutor};

/// A successful match between two orders
pub type SuccessfulMatch = (OrderIdentifier, MatchResult);

impl HandshakeExecutor {
    /// Run a match between two orders
    pub async fn find_match<'a, I>(
        &self,
        order: &Order,
        balance: &Balance,
        price: FixedPoint,
        target_orders: I,
    ) -> Result<Option<SuccessfulMatch>, HandshakeManagerError>
    where
        I: Iterator<Item = &'a OrderIdentifier>,
    {
        let min_quote = self.min_fill_size;
        self.find_match_with_min_quote_amount(order, balance, price, min_quote, target_orders).await
    }

    /// Try a match with a minimum quote amount specified
    pub async fn find_match_with_min_quote_amount<'a, I>(
        &self,
        order: &Order,
        balance: &Balance,
        price: FixedPoint,
        min_quote_amount: Amount,
        target_orders: I,
    ) -> Result<Option<SuccessfulMatch>, HandshakeManagerError>
    where
        I: Iterator<Item = &'a OrderIdentifier>,
    {
        // Match against each other order in the local book
        for order_id in target_orders.into_iter() {
            // Lookup the other order and attempt to match with it
            let (order2, balance2) =
                match self.state.get_managed_order_and_balance(order_id).await? {
                    Some((order, balance)) => (order, balance),
                    None => continue,
                };

            // If a match is successful, return the result
            let res = self.try_match(order, &order2, balance, &balance2, price, min_quote_amount);
            if let Some(match_result) = res {
                return Ok(Some((*order_id, match_result)));
            }
        }

        Ok(None)
    }

    /// Try to match two orders, return the `MatchResult` if a match is found
    fn try_match(
        &self,
        o1: &Order,
        o2: &Order,
        b1: &Balance,
        b2: &Balance,
        price: FixedPoint,
        min_quote_amount: Amount,
    ) -> Option<MatchResult> {
        // Match the orders
        let min_base_amount = Amount::max(o1.min_fill_size, o2.min_fill_size);
        let min_quote_amount = u128::max(min_quote_amount, self.min_fill_size);

        match_orders_with_min_base_amount(
            &o1.clone().into(),
            &o2.clone().into(),
            b1,
            b2,
            min_quote_amount,
            min_base_amount,
            price,
        )
    }

    /// Get the execution price for an order
    pub(crate) async fn get_execution_price_for_order(
        &self,
        order: &OrderIdentifier,
    ) -> Result<TimestampedPriceFp, HandshakeManagerError> {
        let (base, quote) = self.token_pair_for_order(order).await?;
        self.get_execution_price(&base, &quote)
    }

    /// Fetch the execution price for an order
    pub(crate) fn get_execution_price(
        &self,
        base: &Token,
        quote: &Token,
    ) -> Result<TimestampedPriceFp, HandshakeManagerError> {
        let state = self.price_streams.get_state(base, quote);
        let state = &state.into_nominal().ok_or_else(|| {
            HandshakeManagerError::price_reporter(format!("No price data for {base} / {quote}"))
        })?;
        let price: TimestampedPrice = state.into();

        // Correct the price for decimals
        let corrected_price = price
            .get_decimal_corrected_price(base, quote)
            .map_err(err_str!(HandshakeManagerError::NoPriceData))?;
        Ok(corrected_price.into())
    }
}
