//! Defines the PriceReporterExecutor, the handler that is responsible
//! for executing individual PriceReporterJobs.

use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
    thread::JoinHandle,
};

use atomic_float::AtomicF64;
use common::{
    new_async_shared,
    types::{
        exchange::{Exchange, PriceReport, PriceReporterState},
        token::{default_exchange_stable, is_pair_named, Token},
        Price,
    },
    AsyncShared,
};
use external_api::bus_message::{price_report_topic, SystemBusMessage};
use itertools::Itertools;
use statrs::statistics::{Data, Median};
use util::get_current_time_millis;

use crate::{errors::PriceReporterError, worker::PriceReporterConfig};

pub mod external_executor;
pub mod native_executor;

// -------------
// | Constants |
// -------------

/// If a pair has not reported an update within
/// MAX_REPORT_AGE_MS (in milliseconds), we pause matches until we receive a more
/// recent price. Note that this threshold cannot be too aggressive, as certain
/// long-tail asset pairs legitimately do not update that often.
const MAX_REPORT_AGE_MS: u64 = 20_000; // 20 seconds
/// If we do not have at least MIN_CONNECTIONS reports, we pause matches until
/// we have enough reports. This only applies to Named tokens, as Unnamed tokens
/// simply use UniswapV3.
const MIN_CONNECTIONS: usize = 1;
/// If a PriceReport is more than MAX_DEVIATION (as a fraction) away
/// from the midpoint, then we pause matches until the prices stabilize.
const MAX_DEVIATION: f64 = 0.01;

/// The number of milliseconds to wait in between sending keepalive messages to
/// the connections
pub const KEEPALIVE_INTERVAL_MS: u64 = 15_000; // 15 seconds
/// The number of milliseconds to wait in between retrying connections
pub const CONN_RETRY_DELAY_MS: u64 = 2_000; // 2 seconds
/// The number of milliseconds in which `MAX_CONN_RETRIES` failures will cause a
/// failure of the price reporter
pub const MAX_CONN_RETRY_WINDOW_MS: u64 = 60_000; // 1 minute
/// The maximum number of retries to attempt before giving up on a connection
pub const MAX_CONN_RETRIES: usize = 5;

/// The number of milliseconds to wait in between sending price report updates
pub const PRICE_REPORT_INTERVAL_MS: u64 = 1_000; // 1 second

// ---------
// | TYPES |
// ---------

/// The PriceReporter worker is a wrapper around the
/// PriceReporterExecutor, handling and dispatching jobs to the executor
/// for spin-up and shut-down of individual PriceReporters.
pub struct PriceReporter {
    /// The config for the PriceReporter
    pub(super) config: PriceReporterConfig,
    /// The single thread that joins all individual PriceReporter threads
    pub(super) manager_executor_handle: Option<JoinHandle<PriceReporterError>>,
}

/// The state of a price stream for a given (exchange, base, quote).
/// Uses atomic primitives to allow for hardware synchronized update streaming
#[derive(Debug, Default)]
pub struct AtomicPriceStreamState {
    /// The price of the pair on the exchange
    price: AtomicF64,
    /// The time at which the last price was received from the exchange
    last_received: AtomicU64,
}

impl AtomicPriceStreamState {
    /// Update the state of the price stream
    pub fn new_price(&self, price: Price, timestamp: u64) {
        // These operations are not transactionally related, so there is a chance
        // for a race in between updating the timestamp and the price. This is
        // generally okay as the timestamp is only used for determining staleness
        // and given a race the timestamp will be very close to correct
        self.price.store(price, Ordering::Relaxed);
        self.last_received.store(timestamp, Ordering::Relaxed);
    }

    /// Read the price and timestamp
    pub fn read_price(&self) -> (Price, u64) {
        (self.price.load(Ordering::Relaxed), self.last_received.load(Ordering::Relaxed))
    }
}

/// A shareable mapping between (exchange, base, quote) and the most recent
/// state of the associated price stream
#[derive(Clone, Debug)]
pub struct SharedPriceStreamStates(
    AsyncShared<HashMap<(Exchange, Token, Token), AtomicPriceStreamState>>,
);

impl Default for SharedPriceStreamStates {
    fn default() -> Self {
        Self(new_async_shared(HashMap::new()))
    }
}

impl SharedPriceStreamStates {
    /// Initialize the state for the given (exchange, base, quote) price stream
    pub async fn initialize_state(&self, exchange: Exchange, base: Token, quote: Token) {
        let mut price_stream_states = self.0.write().await;

        price_stream_states.insert((exchange, base, quote), AtomicPriceStreamState::default());
    }

    /// Returns whether or not the price stream state is initialized for the
    /// given (exchange, base, quote) is indexed in the mapping, indicating
    /// whether or not it's been initialized
    pub async fn state_is_initialized(
        &self,
        exchange: Exchange,
        base: Token,
        quote: Token,
    ) -> bool {
        let price_stream_states = self.0.read().await;

        price_stream_states.contains_key(&(exchange, base, quote))
    }

    /// Clear all price states, returning the keys that were cleared
    pub async fn clear_states(&self) -> Vec<(Exchange, Token, Token)> {
        let mut price_stream_states = self.0.write().await;

        let keys = price_stream_states.keys().cloned().collect();
        price_stream_states.clear();

        keys
    }

    /// Remove the state for the given (exchange, base, quote) price stream
    pub async fn remove_state(&self, exchange: Exchange, base: Token, quote: Token) {
        let mut price_stream_states = self.0.write().await;

        price_stream_states.remove(&(exchange, base, quote));
    }

    /// Update the price state for the given (exchange, base, quote)
    pub async fn new_price(
        &self,
        exchange: Exchange,
        base: Token,
        quote: Token,
        price: Price,
        timestamp: u64,
    ) -> Result<(), String> {
        let price_stream_states = self.0.read().await;

        let price_state = price_stream_states
            .get(&(exchange, base.clone(), quote.clone()))
            .ok_or(format!("Price stream state not found for ({exchange}, {base}, {quote})",))?;

        price_state.new_price(price, timestamp);

        Ok(())
    }

    /// Get the state of the price reporter for the given token pair
    pub async fn get_state(
        &self,
        base_token: Token,
        quote_token: Token,
        config: &PriceReporterConfig,
    ) -> PriceReporterState {
        // We don't currently support unnamed pairs
        if !is_pair_named(&base_token, &quote_token) {
            return PriceReporterState::UnsupportedPair(base_token, quote_token);
        }

        // Fetch the most recent Binance price
        match self.get_latest_price(Exchange::Binance, &base_token, &quote_token).await {
            None => PriceReporterState::NotEnoughDataReported(0),
            Some((price, ts)) => {
                // Fetch the most recent prices from all other exchanges
                let mut exchange_prices = Vec::new();
                let supported_exchanges =
                    get_supported_exchanges(&base_token, &quote_token, config);
                for exchange in supported_exchanges {
                    if let Some((price, ts)) =
                        self.get_latest_price(exchange, &base_token, &quote_token).await
                    {
                        exchange_prices.push((exchange, (price, ts)));
                    }
                }

                // Compute the state of the price reporter
                compute_price_reporter_state(base_token, quote_token, price, ts, &exchange_prices)
            },
        }
    }

    /// Compute a price report for the given token pair and publish it to the
    /// system bus
    pub async fn publish_price_report(
        &self,
        base: Token,
        quote: Token,
        config: &PriceReporterConfig,
    ) {
        let topic_name = price_report_topic(&base, &quote);
        if config.system_bus.has_listeners(&topic_name) {
            if let PriceReporterState::Nominal(report) = self.get_state(base, quote, config).await {
                config.system_bus.publish(topic_name, SystemBusMessage::PriceReport(report));
            }
        }
    }

    /// Get the latest price for the given exchange and token pair.
    ///
    /// If the pair is eligible, we convert the price through the default stable
    /// quote for the exchange.
    async fn get_latest_price(
        &self,
        exchange: Exchange,
        base_token: &Token,
        quote_token: &Token,
    ) -> Option<(Price, u64)> {
        if eligible_for_stable_quote_conversion(base_token, quote_token, &exchange) {
            self.convert_through_default_stable(base_token, quote_token, exchange).await
        } else {
            self.0
                .read()
                .await
                .get(&(exchange, base_token.clone(), quote_token.clone()))
                .map(|state| state.read_price())
        }
    }

    /// Converts the price for the given pair through the default stable quote
    /// asset for the exchange
    async fn convert_through_default_stable(
        &self,
        base_token: &Token,
        quote_token: &Token,
        exchange: Exchange,
    ) -> Option<(Price, u64)> {
        let states = self.0.read().await;

        let default_stable = default_exchange_stable(&exchange);

        // Get the base / default stable price
        let (base_price, base_ts) =
            states.get(&(exchange, base_token.clone(), default_stable.clone()))?.read_price();

        // Get the quote / default stable price
        let (quote_price, quote_ts) =
            states.get(&(exchange, quote_token.clone(), default_stable.clone()))?.read_price();

        // The converted price = (base / default stable) / (quote / default stable)
        let price = base_price / quote_price;

        // We take the minimum of the two timestamps, so we err on the side of safety
        // and call a price stale if one of the two price streams is stale
        let ts = base_ts.min(quote_ts);

        Some((price, ts))
    }

    /// For the requested token pair, returns the (exchange, base, quote) price
    /// streams which are necessary to correctly compute the price for that
    /// pair which are not already initialized
    async fn missing_streams_for_pair(
        &self,
        requested_base: Token,
        requested_quote: Token,
        config: &PriceReporterConfig,
    ) -> Vec<(Exchange, Token, Token)> {
        let mut missing_streams = Vec::new();
        let req_streams = required_streams_for_pair(&requested_base, &requested_quote, config);

        for (exchange, base, quote) in req_streams {
            if !self.state_is_initialized(exchange, base.clone(), quote.clone()).await {
                missing_streams.push((exchange, base, quote));
            }
        }

        missing_streams
    }
}

// -----------
// | HELPERS |
// -----------

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

/// Returns whether or not the given exchange lists both the tokens in the pair
/// separately
pub fn exchange_lists_pair_tokens(
    exchange: Exchange,
    base_token: &Token,
    quote_token: &Token,
) -> bool {
    let listing_exchanges = get_listing_exchanges(base_token, quote_token);
    listing_exchanges.contains(&exchange)
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
        .filter(|(exchange, (price, ts))| {
            exchange != &Exchange::Binance
                && *price != Price::default()
                && price.is_finite()
                && !ts_too_stale(*ts).0
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
