//! Utility functions for the price state module

use common::types::{
    exchange::{Exchange, PriceReport, PriceReporterState},
    price::Price,
    token::{Token, USD_TICKER, default_exchange_stable},
};
use itertools::Itertools;
use statrs::statistics::{Data, Median};
use util::get_current_time_millis;

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

// --------------------
// | Exchange Support |
// --------------------

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

/// Returns whether or not the given pair on the given exchange may have its
/// price converted through the default stable quote asset for the exchange.
pub fn eligible_for_stable_quote_conversion(
    base: &Token,
    quote: &Token,
    exchange: &Exchange,
) -> bool {
    if base.is_stablecoin() || !quote.is_stablecoin() {
        return false;
    }

    // We assume a 1:1 USD:USDC for Coinbase markets
    let default_stable = default_exchange_stable(exchange);
    let usd = Token::from_ticker(USD_TICKER);
    if default_stable == usd {
        return false;
    }

    quote != &default_exchange_stable(exchange)
}

// ---------------------
// | State Computation |
// ---------------------

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
