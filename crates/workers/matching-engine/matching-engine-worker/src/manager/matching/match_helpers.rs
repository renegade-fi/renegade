//! Helpers for matching orders

use alloy::primitives::Address;
use circuit_types::Amount;
use matching_engine_core::SuccessfulMatch;
use types_account::{MatchingPoolName, account::order::Order, pair::Pair};
use types_core::{AccountId, TimestampedPriceFp};

use crate::{error::MatchingEngineError, executor::MatchingEngineExecutor};

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
        let res = self
            .matching_engine
            .find_match(aid, order.ring, pair, input_range, pool, price)
            .filter(|res| self.validate_min_fill_size(res));

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
            Some(pool) => {
                self.matching_engine.find_match_external(order.ring, pair, input_range, pool, price)
            },
            None => self.matching_engine.find_match_external_all_pools(
                order.ring,
                pair,
                input_range,
                price,
            ),
        }
        .filter(|res| self.validate_min_fill_size(res));

        Ok(res)
    }

    /// Fetch the execution price for an order
    ///
    /// Returns the price in units of output token / input token
    pub(crate) fn get_execution_price(
        &self,
        pair: &Pair,
    ) -> Result<TimestampedPriceFp, MatchingEngineError> {
        self.price_streams
            .get_output_quoted_price(pair)
            .map(TimestampedPriceFp::from)
            .map_err(MatchingEngineError::no_price)
    }

    /// Validate that the minimum fill size is not violated by an order
    pub fn validate_min_fill_size(&self, res: &SuccessfulMatch) -> bool {
        let quote_volume = res.match_result.quote_token_volume();
        quote_volume >= self.min_fill_size
    }

    /// Check if an asset is disabled for matching
    pub(crate) fn is_asset_disabled(&self, addr: &Address) -> bool {
        self.disabled_assets.contains(addr)
    }
}
