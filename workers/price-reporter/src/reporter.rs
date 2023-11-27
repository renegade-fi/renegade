//! Defines the PriceReporter, which is responsible for computing median
//! PriceReports by managing individual ExchangeConnections in a fault-tolerant
//! manner.
use atomic_float::AtomicF64;
use common::types::exchange::{
    Exchange, ExchangeConnectionState, PriceReport, PriceReporterState, ALL_EXCHANGES,
};
use common::types::token::Token;
use common::types::Price;
use external_api::bus_message::{price_report_topic_name, SystemBusMessage};
use futures_util::future::try_join_all;
use itertools::Itertools;
use statrs::statistics::{Data, Median};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use std::{collections::HashMap, sync::Arc};
use system_bus::SystemBus;
use tokio::time::Instant;
use tokio_stream::{StreamExt, StreamMap};
use tracing::log;
use util::get_current_time_seconds;

use crate::exchange::connect_exchange;
use crate::exchange::connection::ExchangeConnection;

use super::MEDIAN_SOURCE_NAME;
use super::{errors::ExchangeConnectionError, worker::PriceReporterManagerConfig};

// -------------
// | Constants |
// -------------

/// If none of the ExchangeConnections have reported an update within
/// MAX_REPORT_AGE (in milliseconds), we pause matches until we receive a more
/// recent price. Note that this threshold cannot be too aggressive, as certain
/// long-tail asset pairs legitimately do not update that often.
const MAX_REPORT_AGE_MS: u64 = 20_000; // 20 seconds
/// If we do not have at least MIN_CONNECTIONS reports, we pause matches until
/// we have enough reports. This only applies to Named tokens, as Unnamed tokens
/// simply use UniswapV3.
const MIN_CONNECTIONS: usize = 1;
/// If a single PriceReport is more than MAX_DEVIATION (as a fraction) away from
/// the midpoint, then we pause matches until the prices stabilize.
const MAX_DEVIATION: f64 = 0.02;

/// The number of milliseconds to wait in between sending keepalive messages to
/// the connections
const KEEPALIVE_INTERVAL_MS: u64 = 15_000; // 15 seconds
/// The number of milliseconds to wait in between retrying connections
const CONN_RETRY_DELAY_MS: u64 = 2_000; // 2 seconds
/// The number of milliseconds in which `MAX_CONN_RETRIES` failures will cause a
/// failure of the price reporter
const MAX_CONN_RETRY_WINDOW_MS: u64 = 60_000; // 1 minute
/// The maximum number of retries to attempt before giving up on a connection
const MAX_CONN_RETRIES: usize = 5;

/// The number of milliseconds to wait in between sending median price report
/// updates
const MEDIAN_PRICE_REPORT_INTERVAL_MS: u64 = 1_000; // 1 second

/// The price reporter handles opening connections to exchanges, and computing
/// price reports and medians from the exchange data
#[derive(Clone, Debug)]
pub struct PriceReporter {
    /// The base Token (e.g., WETH)
    base_token: Token,
    /// The quote Token (e.g., USDC)
    quote_token: Token,
    /// The shared memory map from exchange to most recent price
    /// and reporting timestamp
    exchange_info: AtomicPriceStreamState,
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
    pub fn new_from_exchanges(exchanges: Vec<Exchange>) -> Self {
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

impl PriceReporter {
    // ----------------------
    // | External Interface |
    // ----------------------

    /// Creates a new PriceReporter.
    pub async fn new(
        base_token: Token,
        quote_token: Token,
        config: PriceReporterManagerConfig,
    ) -> Result<Self, ExchangeConnectionError> {
        let supported_exchanges =
            Self::compute_supported_exchanges_for_pair(&base_token, &quote_token, &config);

        // Create shared memory that the `ConnectionMuxer` will use to communicate with
        // the `PriceReporter`
        let shared_exchange_state =
            AtomicPriceStreamState::new_from_exchanges(supported_exchanges.clone());

        // Spawn a thread to manage the connections
        let connection_muxer = ConnectionMuxer::new(
            base_token.clone(),
            quote_token.clone(),
            config.clone(),
            supported_exchanges,
            shared_exchange_state.clone(),
        );

        tokio::spawn({
            let base_token = base_token.clone();
            let quote_token = quote_token.clone();
            async move {
                if let Err(e) = connection_muxer.execution_loop().await {
                    log::error!("Error in ConnectionMuxer for {base_token}-{quote_token}: {e}");
                }
            }
        });

        // Spawn a thread to stream median price reports
        let self_ = Self { base_token, quote_token, exchange_info: shared_exchange_state };

        let self_clone = self_.clone();
        tokio::spawn(async move { self_clone.median_streamer_loop(config.system_bus).await });

        Ok(self_)
    }

    /// Non-blocking report of the latest PriceReporterState for the median
    pub fn peek_median(&self) -> PriceReporterState {
        self.get_state()
    }

    /// Non-blocking report of the latest ExchangeConnectionState for all
    /// exchanges
    pub fn peek_all_exchanges(&self) -> HashMap<Exchange, ExchangeConnectionState> {
        let mut exchange_connection_states = HashMap::<Exchange, ExchangeConnectionState>::new();

        for exchange in ALL_EXCHANGES.iter() {
            let state = if let Some((price, ts)) = self.exchange_info.read_price(exchange) {
                if price == Price::default() {
                    ExchangeConnectionState::NoDataReported
                } else {
                    ExchangeConnectionState::Nominal(self.price_report_from_price(price, ts))
                }
            } else {
                ExchangeConnectionState::Unsupported
            };

            exchange_connection_states.insert(*exchange, state);
        }
        exchange_connection_states
    }

    // -----------
    // | Helpers |
    // -----------

    /// An execution loop that streams median price reports to the system bus
    async fn median_streamer_loop(&self, system_bus: SystemBus<SystemBusMessage>) {
        let topic_name =
            price_report_topic_name(MEDIAN_SOURCE_NAME, &self.base_token, &self.quote_token);

        loop {
            if system_bus.has_listeners(&topic_name) {
                if let PriceReporterState::Nominal(report) = self.get_state() {
                    system_bus
                        .publish(topic_name.clone(), SystemBusMessage::PriceReportMedian(report));
                }
            }

            tokio::time::sleep(Duration::from_millis(MEDIAN_PRICE_REPORT_INTERVAL_MS)).await;
        }
    }

    /// Returns if this PriceReport is of a "Named" token pair (as opposed to an
    /// "Unnamed" pair) If the PriceReport is Named, then the prices are
    /// denominated in USD and largely derived from centralized exchanges.
    /// If the PriceReport is Unnamed, then the prices are derived from
    /// UniswapV3 and do not do fixed-point decimals adjustment.
    fn is_named(&self) -> bool {
        self.base_token.is_named() && self.quote_token.is_named()
    }

    /// Returns the set of supported exchanges on the pair
    fn compute_supported_exchanges_for_pair(
        base_token: &Token,
        quote_token: &Token,
        config: &PriceReporterManagerConfig,
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

    /// Construct a price report from a given price
    fn price_report_from_price(&self, price: Price, local_timestamp: u64) -> PriceReport {
        PriceReport {
            base_token: self.base_token.clone(),
            quote_token: self.quote_token.clone(),
            exchange: None,
            midpoint_price: price,
            local_timestamp,
            reported_timestamp: None,
        }
    }

    /// Given a PriceReport for each Exchange, compute the current
    /// PriceReporterState. We check for various issues (delayed prices, no
    /// data yet received, etc.), and if no issues are found, compute the
    /// median PriceReport
    fn get_state(&self) -> PriceReporterState {
        // If the Token pair is Unnamed, then we simply report the UniswapV3 price if
        // one exists.
        if !self.is_named() {
            let (uni_price, uni_ts) = self.exchange_info.read_price(&Exchange::UniswapV3).unwrap();
            if uni_price == Price::default() {
                return PriceReporterState::NotEnoughDataReported(0);
            } else {
                return PriceReporterState::Nominal(
                    self.price_report_from_price(uni_price, uni_ts),
                );
            }
        }

        // Collect all non-zero PriceReports and ensure that we have enough.
        let (non_zero_prices, timestamps): (Vec<Price>, Vec<u64>) = ALL_EXCHANGES
            .iter()
            .filter_map(|exchange| self.exchange_info.read_price(exchange))
            .filter(|(price, _)| *price != Price::default() && price.is_finite())
            .unzip();

        // Ensure that we have enough data to create a median
        if non_zero_prices.len() < MIN_CONNECTIONS {
            return PriceReporterState::NotEnoughDataReported(non_zero_prices.len());
        }

        // Compute the median price report
        let median_midpoint_price = Data::new(non_zero_prices.clone()).median();
        let median_ts =
            Data::new(timestamps.iter().map(|ts| *ts as f64).collect_vec()).median() as u64;
        let median_price_report = PriceReport {
            base_token: self.base_token.clone(),
            quote_token: self.quote_token.clone(),
            exchange: None,
            midpoint_price: median_midpoint_price,
            local_timestamp: median_ts,
            reported_timestamp: None,
        };

        // Check that the most recent timestamp is not too old
        let most_recent_report = timestamps.iter().max().unwrap();
        let time_diff = get_current_time_seconds() - most_recent_report;
        if time_diff > MAX_REPORT_AGE_MS {
            return PriceReporterState::DataTooStale(median_price_report, time_diff);
        }

        // Ensure that there is not too much deviation between the prices
        let max_deviation = non_zero_prices
            .iter()
            .map(|price| (price - median_midpoint_price).abs() / median_midpoint_price)
            .fold(0f64, |a, b| a.max(b));
        if non_zero_prices.len() > 1 && max_deviation > MAX_DEVIATION {
            return PriceReporterState::TooMuchDeviation(median_price_report, max_deviation);
        }

        PriceReporterState::Nominal(median_price_report)
    }
}

// -------------------
// | ConnectionMuxer |
// -------------------

/// The connection muxer manages a set of websocket connections abstracted as
/// `ExchangeConnection`s. It is responsible for restarting connections that
/// fail, and communicating the latest price reports to the `PriceReporter` via
/// an atomic shared memory primitive
struct ConnectionMuxer {
    /// The base token that the managed connections are reporting on
    base_token: Token,
    /// The quote token that the managed connections are reporting on
    quote_token: Token,
    /// The config for the price reporter
    config: PriceReporterManagerConfig,
    /// The set of exchanges connected
    exchanges: Vec<Exchange>,
    /// The shared memory map from exchange to most recent price
    exchange_state: AtomicPriceStreamState,
    /// Tracks the number of failures in connecting to an exchange
    ///
    /// Maps from a given exchange to a vector of timestamps representing
    /// past failures within the last `MAX_CONN_RETRY_WINDOW_MS` milliseconds
    exchange_retries: HashMap<Exchange, Vec<Instant>>,
}

impl ConnectionMuxer {
    /// Create a new `ConnectionMuxer`
    pub fn new(
        base_token: Token,
        quote_token: Token,
        config: PriceReporterManagerConfig,
        exchanges: Vec<Exchange>,
        exchange_state: AtomicPriceStreamState,
    ) -> Self {
        Self {
            base_token,
            quote_token,
            config,
            exchanges,
            exchange_state,
            exchange_retries: HashMap::new(),
        }
    }

    /// Start the connection muxer
    pub async fn execution_loop(mut self) -> Result<(), ExchangeConnectionError> {
        // Start a keepalive timer
        let delay = tokio::time::sleep(Duration::from_millis(KEEPALIVE_INTERVAL_MS));
        tokio::pin!(delay);

        // Build a map of connections to multiplex from
        let mut stream_map = self.initialize_connections().await?;

        loop {
            tokio::select! {
                // Keepalive timer
                _ = &mut delay => {
                    for exchange in stream_map.values_mut() {
                        if let Err(e) = exchange.send_keepalive().await {
                            log::error!("Error sending keepalive to exchange: {e}");
                        }
                    }

                    delay.as_mut().reset(Instant::now() + Duration::from_millis(KEEPALIVE_INTERVAL_MS));
                },

                // New price streamed from an exchange
                stream_elem = stream_map.next() => {
                    if let Some((exchange, res)) = stream_elem {
                        match res {
                            Ok(price) => {
                                // Do not update if the price is default, simply let the price age
                                if price == Price::default() {
                                    continue;
                                }

                                let ts = get_current_time_seconds();
                                self.exchange_state
                                    .new_price(exchange, price, ts);

                                // Stream a price update to the bus
                                self.config.system_bus.publish(
                                    price_report_topic_name(&exchange.to_string(), &self.base_token, &self.quote_token),
                                    SystemBusMessage::PriceReportExchange(PriceReport {
                                        base_token: self.base_token.clone(),
                                        quote_token: self.quote_token.clone(),
                                        exchange: Some(exchange),
                                        midpoint_price: price,
                                        local_timestamp: ts,
                                        reported_timestamp: None
                                    }),
                                );
                            },

                            Err(e) => {
                                // Restart the connection
                                log::error!("Error streaming from {exchange}: {e}, restarting connection...");
                                loop {
                                    match self.retry_connection(exchange).await {
                                        Ok(conn) => {
                                            log::info!("Successfully reconnected to {exchange}");
                                            stream_map.insert(exchange, conn);
                                        }
                                        Err(ExchangeConnectionError::MaxRetries(_)) => {
                                            log::error!("Max retries ({MAX_CONN_RETRIES}) exceeded, unable to connect to {exchange}... removing from data sources");
                                            stream_map.remove(&exchange);
                                            break;
                                        }
                                        _ => {
                                            log::warn!("Connection retry attempt failed");
                                        },
                                    }
                                }
                            }

                        }
                    }
                }
            }
        }
    }

    /// Sets up the initial connections to each exchange and places them in a
    /// `StreamMap` for multiplexing
    async fn initialize_connections<'a>(
        &mut self,
    ) -> Result<StreamMap<Exchange, Box<dyn ExchangeConnection>>, ExchangeConnectionError> {
        // We do not use a more convenient stream here for concurrent init because of:
        //   https://github.com/rust-lang/rust/issues/102211
        // In specific, streams in async blocks sometimes have lifetimes erased which
        // makes it impossible for the compiler to infer auto-traits like `Send`
        let futures = self
            .exchanges
            .iter()
            .map(|exchange| {
                let base_token = self.base_token.clone();
                let quote_token = self.quote_token.clone();
                let config = self.config.clone();

                async move { connect_exchange(&base_token, &quote_token, &config, *exchange).await }
            })
            .collect::<Vec<_>>();
        let conns = try_join_all(futures.into_iter()).await?;

        // Build a shared, mapped stream from the individual exchange streams
        Ok(self.exchanges.clone().into_iter().zip(conns.into_iter()).collect::<StreamMap<_, _>>())
    }

    /// Retries an exchange connection after it has failed
    async fn retry_connection(
        &mut self,
        exchange: Exchange,
    ) -> Result<Box<dyn ExchangeConnection>, ExchangeConnectionError> {
        // Increment the retry count and filter out old requests
        let now = Instant::now();
        let retry_timestamps = self.exchange_retries.entry(exchange).or_default();
        retry_timestamps
            .retain(|ts| now.duration_since(*ts) < Duration::from_millis(MAX_CONN_RETRY_WINDOW_MS));

        // Add the current timestamp to the set of retries
        retry_timestamps.push(now);

        if retry_timestamps.len() >= MAX_CONN_RETRIES {
            return Err(ExchangeConnectionError::MaxRetries(exchange));
        }

        // Add delay before retrying
        tokio::time::sleep(Duration::from_secs(CONN_RETRY_DELAY_MS)).await;

        // Reconnect
        log::info!("Retrying connection to {exchange}");
        connect_exchange(&self.base_token, &self.quote_token, &self.config, exchange).await
    }
}
