//! Defines the PriceReporterExecutor, the handler that is responsible
//! for executing individual PriceReporterJobs.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    thread::JoinHandle,
};

use atomic_float::AtomicF64;
use common::types::{
    exchange::{Exchange, PriceReport, PriceReporterState},
    token::Token,
    Price,
};
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
/// MAX_REPORT_AGE (in milliseconds), we pause matches until we receive a more
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

/// The state streamed from the connection multiplexer to the price reporter
/// Uses atomic primitives to allow for hardware synchronized update streaming
#[derive(Clone, Debug)]
pub struct AtomicPriceStreamState {
    /// The price information for each exchange, updated by the
    /// `ConnectionMuxer`
    price_map: HashMap<Exchange, Arc<AtomicF64>>,
    /// A map indicating the time at which the last price was received from each
    /// exchange
    last_received: HashMap<Exchange, Arc<AtomicU64>>,
}

impl AtomicPriceStreamState {
    /// Construct a new price stream state instance from a set fo exchanges
    pub fn new_from_exchanges(exchanges: &[Exchange]) -> Self {
        Self {
            price_map: exchanges
                .iter()
                .map(|exchange| (*exchange, Arc::new(AtomicF64::new(0.))))
                .collect(),
            last_received: exchanges
                .iter()
                .map(|exchange| (*exchange, Arc::new(AtomicU64::new(0))))
                .collect(),
        }
    }

    /// Add a new price report for a given exchange
    pub fn new_price(&self, exchange: Exchange, price: Price, timestamp: u64) {
        // These operations are not transactionally related, so there is a chance
        // for a race in between updating the timestamp and the price. This is
        // generally okay as the timestamp is only used for determining staleness
        // and given a race the timestamp will be very close to correct
        self.price_map.get(&exchange).unwrap().store(price, Ordering::Relaxed);
        self.last_received.get(&exchange).unwrap().store(timestamp, Ordering::Relaxed);
    }

    /// Read the price and timestamp from a given exchange
    pub fn read_price(&self, exchange: &Exchange) -> Option<(Price, u64)> {
        Some((
            self.price_map.get(exchange)?.load(Ordering::Relaxed),
            self.last_received.get(exchange)?.load(Ordering::Relaxed),
        ))
    }
}

// -----------
// | HELPERS |
// -----------

/// Returns the set of supported exchanges on the pair
pub fn compute_supported_exchanges_for_pair(
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
    (time_diff > MAX_REPORT_AGE_MS, time_diff)
}
