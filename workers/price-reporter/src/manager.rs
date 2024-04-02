//! Defines the PriceReporterExecutor, the handler that is responsible
//! for executing individual PriceReporterJobs.

use std::{
    collections::{HashMap, HashSet},
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
use external_api::bus_message::{price_report_topic_name, SystemBusMessage};
use itertools::Itertools;
use statrs::statistics::{Data, Median};
use util::get_current_time_seconds;

use crate::{errors::PriceReporterError, worker::PriceReporterConfig};

pub mod external_executor;
pub mod native_executor;

// -------------
// | Constants |
// -------------

/// If a pair has not reported an update within
/// MAX_REPORT_AGE (in seconds), we pause matches until we receive a more
/// recent price. Note that this threshold cannot be too aggressive, as certain
/// long-tail asset pairs legitimately do not update that often.
const MAX_REPORT_AGE: u64 = 20; // 20 seconds
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

/// A type alias for a (base, quote) token pair
type Pair = (Token, Token);

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

/// Manages the global state of all price streams, exposing a shareable,
/// synchronized interface for updating and querying the state of price streams,
/// as well as logic for computing the state of the price reporter for a given
/// token pair
#[derive(Clone, Debug)]
pub struct PriceStreamStatesManager {
    /// The configuration for the price reporter
    config: PriceReporterConfig,
    /// A shareable mapping between (exchange, base, quote) and the most recent
    /// state of the associated price stream
    price_stream_states: AsyncShared<HashMap<(Exchange, Token, Token), AtomicPriceStreamState>>,
    /// The set of top-level pairs for which prices have been externally
    /// requested from the price reporter, i.e. via a `StreamPrice` or
    /// `PeekPrice` job
    requested_pairs: AsyncShared<HashSet<Pair>>,
    /// A mapping between a conversion pair (i.e., a pair which was not
    /// requested externally but is used to compute the price of a requested
    /// pair) and the requested pairs that depend on it
    converted_pairs: AsyncShared<HashMap<Pair, Vec<Pair>>>,
}

impl PriceStreamStatesManager {
    /// Create a new PriceStreamStatesManager with the given configuration
    pub fn new(config: PriceReporterConfig) -> Self {
        Self {
            config,
            price_stream_states: new_async_shared(HashMap::new()),
            requested_pairs: new_async_shared(HashSet::new()),
            converted_pairs: new_async_shared(HashMap::new()),
        }
    }

    /// Initialize the state for the given (exchange, base, quote) price stream
    pub async fn initialize_state(&self, exchange: Exchange, base: Token, quote: Token) {
        let mut price_stream_states = self.price_stream_states.write().await;

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
        let price_stream_states = self.price_stream_states.read().await;

        price_stream_states.contains_key(&(exchange, base, quote))
    }

    /// Register the given (base, quote) pair as a top-level, requested pair
    pub async fn register_requested_pair(&self, base: Token, quote: Token) {
        let mut requested_pairs = self.requested_pairs.write().await;

        requested_pairs.insert((base, quote));
    }

    /// Register the conversion pair being used for the given requested pair
    pub async fn register_conversion_pair(
        &self,
        requested_pair: (Token, Token),
        conversion_pair: (Token, Token),
    ) {
        let mut converted_pairs = self.converted_pairs.write().await;

        // Add the requested pair as a dependent of the conversion pair if it already
        // exists, otherwise insert the conversion pair with the requested pair
        // as a dependent
        converted_pairs
            .entry(conversion_pair)
            .and_modify(|pairs| pairs.push(requested_pair.clone()))
            .or_insert(vec![requested_pair]);
    }

    /// Clear all price states, returning the keys that were cleared
    pub async fn clear_states(&self) -> Vec<(Exchange, Token, Token)> {
        let mut price_stream_states = self.price_stream_states.write().await;

        let keys = price_stream_states.keys().cloned().collect();
        price_stream_states.clear();

        keys
    }

    /// Remove the state for the given (exchange, base, quote) price stream
    pub async fn remove_state(&self, exchange: Exchange, base: Token, quote: Token) {
        let mut price_stream_states = self.price_stream_states.write().await;

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
        let price_stream_states = self.price_stream_states.read().await;

        let price_state = price_stream_states
            .get(&(exchange, base.clone(), quote.clone()))
            .ok_or(format!("Price stream state not found for ({exchange}, {base}, {quote})",))?;

        price_state.new_price(price, timestamp);

        Ok(())
    }

    /// Get the state of the price reporter for the given token pair
    pub async fn get_state(&self, base_token: Token, quote_token: Token) -> PriceReporterState {
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
                    get_supported_exchanges(&base_token, &quote_token, &self.config);
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

    /// Compute price reports for all pairs whose price is affected by an update
    /// to price for the given (base, quote) pair and publish them to the
    /// system bus
    pub async fn publish_price_reports(&self, base: Token, quote: Token) {
        for (affected_base, affected_quote) in self.get_pairs_to_report(base, quote).await {
            let topic_name = price_report_topic_name(&affected_base, &affected_quote);
            if self.config.system_bus.has_listeners(&topic_name) {
                if let PriceReporterState::Nominal(report) =
                    self.get_state(affected_base.clone(), affected_quote.clone()).await
                {
                    self.config
                        .system_bus
                        .publish(topic_name, SystemBusMessage::PriceReport(report));
                }
            }
        }
    }

    /// Return the pairs for which a new `PriceReport` should be computed if the
    /// given pair has had a price update
    async fn get_pairs_to_report(&self, base: Token, quote: Token) -> Vec<(Token, Token)> {
        let mut pairs_to_report = Vec::new();
        if self.requested_pairs.read().await.contains(&(base.clone(), quote.clone())) {
            pairs_to_report.push((base.clone(), quote.clone()));
        }

        if let Some(dependent_pairs) = self.converted_pairs.read().await.get(&(base, quote)) {
            pairs_to_report.extend(dependent_pairs.clone());
        }

        pairs_to_report
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
            self.price_stream_states
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
        let states = self.price_stream_states.read().await;

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
    ) -> Vec<(Exchange, Token, Token)> {
        let mut missing_streams = Vec::new();
        let req_streams =
            required_streams_for_pair(&requested_base, &requested_quote, &self.config);

        for (exchange, base, quote) in req_streams {
            if !self.state_is_initialized(exchange, base.clone(), quote.clone()).await {
                missing_streams.push((exchange, base, quote));
            }
        }

        missing_streams
    }

    /// For the requested token pair, and the given list of (exchange, base,
    /// quote) tuples for which price streams were initialized, register the
    /// conversion pairs and the requested pair.
    async fn register_pairs(
        &self,
        requested_base: Token,
        requested_quote: Token,
        initialized_streams: &[(Exchange, Token, Token)],
    ) {
        for (_, base, quote) in initialized_streams {
            if quote != &requested_quote {
                // This is a conversion pair, i.e. either (base, default stable) or (quote,
                // default stable)
                self.register_conversion_pair(
                    (requested_base.clone(), requested_quote.clone()),
                    (base.clone(), quote.clone()),
                )
                .await;
            } else {
                // This is the requested pair
                self.register_requested_pair(requested_base.clone(), requested_quote.clone()).await;
            }
        }
    }
}

// -----------
// | HELPERS |
// -----------

/// Returns the set of supported exchanges on the pair
pub fn get_supported_exchanges(
    base_token: &Token,
    quote_token: &Token,
    config: &PriceReporterConfig,
) -> Vec<Exchange> {
    // Compute the intersection of the supported exchanges for each of the assets
    // in the pair, filtering for those not configured
    let base_token_supported_exchanges = base_token.supported_exchanges();
    let quote_token_supported_exchanges = quote_token.supported_exchanges();
    base_token_supported_exchanges
        .intersection(&quote_token_supported_exchanges)
        .copied()
        .filter(|exchange| config.exchange_configured(*exchange))
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
    let time_diff = get_current_time_seconds() - ts;
    (time_diff > MAX_REPORT_AGE, time_diff)
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
