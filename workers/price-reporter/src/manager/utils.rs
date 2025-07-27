//! Utilities for the PriceReporter manager

use common::types::{
    exchange::{Exchange, PriceReport, PriceReporterState},
    price::Price,
    token::{Token, default_exchange_stable},
};
use itertools::Itertools;
use statrs::statistics::{Data, Median};
use util::get_current_time_millis;

use crate::worker::PriceReporterConfig;

/// If a pair has not reported an update within
/// MAX_REPORT_AGE_MS (in milliseconds), we pause matches until we receive a
/// more recent price. Note that this threshold cannot be too aggressive, as
/// certain long-tail asset pairs legitimately do not update that often.
const MAX_REPORT_AGE_MS: u64 = 20_000; // 20 seconds
/// If a PriceReport is more than MAX_DEVIATION (as a fraction) away
/// from the midpoint, then we pause matches until the prices stabilize.
const MAX_DEVIATION: f64 = 0.01;
/// If we do not have at least MIN_CONNECTIONS reports, we pause matches until
/// we have enough reports. This only applies to Named tokens, as Unnamed tokens
/// simply use UniswapV3.
const MIN_CONNECTIONS: usize = 1;

/// Returns the set of exchanges that support both tokens in the pair.
///
/// Note: This does not mean that each exchange has a market for the pair,
/// just that it separately lists both tokens.
pub fn get_supported_exchanges(
    base_token: &Token,
    quote_token: &Token,
    config: &PriceReporterConfig,
) -> Vec<Exchange> {
    // Get the exchanges that list both tokens, and filter out the ones that
    // are not configured
    let listing_exchanges = get_listing_exchanges(base_token, quote_token);
    listing_exchanges
        .into_iter()
        .filter(|exchange| config.exchange_configured(*exchange))
        .collect_vec()
}

/// Returns the list of exchanges that list both the base and quote tokens.
///
/// Note: This does not mean that each exchange has a market for the pair,
/// just that it separately lists both tokens.
pub fn get_listing_exchanges(base_token: &Token, quote_token: &Token) -> Vec<Exchange> {
    // Compute the intersection of the supported exchanges for each of the assets
    // in the pair
    let base_token_supported_exchanges = base_token.supported_exchanges();
    let quote_token_supported_exchanges = quote_token.supported_exchanges();
    base_token_supported_exchanges
        .intersection(&quote_token_supported_exchanges)
        .copied()
        .collect_vec()
}

/// Computes the state of the price reporter for the given token pair,
/// checking against the provided exchange prices.
pub fn compute_price_reporter_state(
    base_token: Token,
    quote_token: Token,
    price: f64,
    local_timestamp: u64,
    exchange_prices: &[(Exchange, (Price, u64))],
) -> PriceReporterState {
    if price == Price::default() {
        return PriceReporterState::NotEnoughDataReported(0);
    }

    let price_report = PriceReport { base_token, quote_token, price, local_timestamp };

    // Check that the most recent timestamp is not too old
    let (too_stale, time_diff) = ts_too_stale(local_timestamp);
    if too_stale {
        return PriceReporterState::DataTooStale(price_report, time_diff);
    }

    // Collect all non-zero, non-stale prices from other exchanges and ensure that
    // we have enough.
    let non_zero_prices: Vec<Price> = exchange_prices
        .iter()
        .filter(|(_exchange, (price, ts))| {
            *price != Price::default() && price.is_finite() && !ts_too_stale(*ts).0
        })
        .map(|(_, (price, _))| *price)
        .collect();

    // If we have enough data to create a median, check for deviation against it
    if non_zero_prices.len() < MIN_CONNECTIONS {
        return PriceReporterState::NotEnoughDataReported(non_zero_prices.len());
    }

    // Compute the median price
    let median_midpoint_price = Data::new(non_zero_prices.clone()).median();

    // Ensure that there is not too much deviation between the prices
    let deviation = (price - median_midpoint_price).abs() / median_midpoint_price;
    if deviation > MAX_DEVIATION {
        return PriceReporterState::TooMuchDeviation(price_report, deviation);
    }

    PriceReporterState::Nominal(price_report)
}

/// Returns whether or not the provided timestamp is too stale,
/// and the time difference between the current time and the provided timestamp
fn ts_too_stale(ts: u64) -> (bool, u64) {
    let time_diff = get_current_time_millis() - ts;
    (time_diff > MAX_REPORT_AGE_MS, time_diff)
}

/// Returns the (exchange, base, quote) tuples for which price streams are
/// required to accurately compute the price for the (requested_base,
/// requested_quote) pair
pub fn required_streams_for_pair(
    requested_base: &Token,
    requested_quote: &Token,
    config: &PriceReporterConfig,
) -> Vec<(Exchange, Token, Token)> {
    let mut streams = Vec::new();
    let exchanges = get_supported_exchanges(requested_base, requested_quote, config);
    for exchange in exchanges {
        let pairs =
            if eligible_for_stable_quote_conversion(requested_base, requested_quote, &exchange) {
                let default_stable = default_exchange_stable(&exchange);
                vec![
                    (exchange, requested_base.clone(), default_stable.clone()),
                    (exchange, requested_quote.clone(), default_stable),
                ]
            } else {
                vec![(exchange, requested_base.clone(), requested_quote.clone())]
            };

        streams.extend(pairs);
    }

    streams
}

/// Returns whether or not the given pair on the given exchange may have its
/// price converted through the default stable quote asset for the exchange.
pub fn eligible_for_stable_quote_conversion(
    base: &Token,
    quote: &Token,
    exchange: &Exchange,
) -> bool {
    !base.is_stablecoin() && quote.is_stablecoin() && quote != &default_exchange_stable(exchange)
}
