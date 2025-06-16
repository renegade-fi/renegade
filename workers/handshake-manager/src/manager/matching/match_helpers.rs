//! Helpers for matching orders

use circuit_types::{balance::Balance, fixed_point::FixedPoint, r#match::MatchResult, Amount};
use common::types::{
    exchange::PriceReporterState,
    token::Token,
    wallet::{Order, OrderIdentifier},
    TimestampedPrice,
};
use util::{err_str, matching_engine::match_orders_with_min_base_amount};

use crate::manager::handshake::ERR_NO_PRICE_DATA;
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
    ) -> Result<TimestampedPrice, HandshakeManagerError> {
        let (base, quote) = self.token_pair_for_order(order).await?;
        self.get_execution_price(&base, &quote).await
    }

    /// Fetch the execution price for an order
    pub(crate) async fn get_execution_price(
        &self,
        base: &Token,
        quote: &Token,
    ) -> Result<TimestampedPrice, HandshakeManagerError> {
        let base_addr = base.get_addr().to_string();
        let quote_addr = quote.get_addr().to_string();
        let price_recv = self.request_price(base.clone(), quote.clone())?;
        let price: TimestampedPrice =
            match price_recv.await.map_err(err_str!(HandshakeManagerError::PriceReporter))? {
                PriceReporterState::Nominal(ref report) => report.into(),
                err_state => {
                    return Err(HandshakeManagerError::NoPriceData(format!(
                        "{ERR_NO_PRICE_DATA}: {} / {} {err_state:?}",
                        base_addr, quote_addr,
                    )));
                },
            };

        // Correct the price for decimals
        let corrected_price = price
            .get_decimal_corrected_price(base, quote)
            .map_err(err_str!(HandshakeManagerError::NoPriceData))?;

        Ok(corrected_price)
    }
}
