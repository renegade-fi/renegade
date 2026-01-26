//! Helpers for matching orders

use circuit_types::{Amount, fixed_point::FixedPoint};
use matching_engine_core::SuccessfulMatch;
use types_account::{MatchingPoolName, account::order::Order, pair::Pair};
use types_core::{AccountId, TimestampedPrice, TimestampedPriceFp};
use util::get_current_time_millis;

use crate::{error::MatchingEngineError, executor::MatchingEngineExecutor};

// TODO: Global min fill size
impl MatchingEngineExecutor {
    /// Find an internal match for an order
    pub fn find_internal_match(
        &self,
        aid: AccountId,
        order: &Order,
        matchable: Amount,
        pool: MatchingPoolName,
    ) -> Result<Option<SuccessfulMatch>, MatchingEngineError> {
        // Sample a price to execute the match at
        let pair = order.pair();
        let price = self.get_execution_price(&pair)?;

        // Sanity check the input range
        let input_range = order.min_fill_size()..=matchable;
        if input_range.is_empty() {
            return Ok(None);
        }

        // Forward to the matching engine
        let res = self.matching_engine.find_match(aid, pair, input_range, pool, price);
        Ok(res)
    }

    /// Find an external match for an order
    ///
    /// If `matching_pool` is `None`, the match will search across all pools.
    /// If `Some(pool)`, only orders in that specific pool will be considered.
    pub fn find_external_match(
        &self,
        order: &Order,
        matching_pool: Option<MatchingPoolName>,
    ) -> Result<Option<SuccessfulMatch>, MatchingEngineError> {
        // For an external match, no balance capitalizes the order, so the matchable
        // amount is the same as the intent amount
        let matchable_amount = order.intent().amount_in;

        // Sample a price to execute the match at
        let pair = order.pair();
        let price = self.get_execution_price(&pair)?;

        // Sanity check the input range
        let input_range = order.min_fill_size()..=matchable_amount;
        if input_range.is_empty() {
            return Ok(None);
        }

        // Forward to the matching engine
        let res = match matching_pool {
            Some(pool) => self.matching_engine.find_match_external(pair, input_range, pool, price),
            None => self.matching_engine.find_match_external_all_pools(pair, input_range, price),
        };

        Ok(res)
    }

    /// Fetch the execution price for an order
    pub(crate) fn get_execution_price(
        &self,
        pair: &Pair,
    ) -> Result<TimestampedPriceFp, MatchingEngineError> {
        // Convert the pair to a canonically quoted pair
        let usdc_quoted_pair = pair.to_usdc_quoted().map_err(MatchingEngineError::no_price)?;
        let (base, quote) = (usdc_quoted_pair.in_token(), usdc_quoted_pair.out_token());

        // Fetch the price state for the pair
        let state = self.price_streams.get_state(&base, &quote);
        let state = &state.into_nominal().ok_or_else(|| {
            MatchingEngineError::price_reporter(format!("No price data for {base} / {quote}"))
        })?;
        let price: TimestampedPrice = state.into();

        // Correct the price for decimals
        let corrected_price = price
            .get_decimal_corrected_price(&base, &quote)
            .map_err(MatchingEngineError::no_price)?;
        Ok(corrected_price.into())
    }
}
