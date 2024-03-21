//! Defines the Reporter, which is responsible for computing
//! PriceReports by managing individual ExchangeConnections in a fault-tolerant
//! manner.

use common::types::exchange::{
    Exchange, ExchangeConnectionState, PriceReport, PriceReporterState, ALL_EXCHANGES,
};
use common::types::token::{is_pair_named, Token};
use common::types::Price;
use external_api::bus_message::{price_report_topic_name, SystemBusMessage};
use futures_util::future::try_join_all;
use std::collections::HashMap;
use std::time::Duration;
use system_bus::SystemBus;
use tokio::time::Instant;
use tokio_stream::{StreamExt, StreamMap};
use tracing::{error, info, warn};
use util::get_current_time_seconds;

use crate::exchange::connect_exchange;
use crate::exchange::connection::ExchangeConnection;
use crate::manager::{
    compute_price_reporter_state, get_supported_exchanges, AtomicPriceStreamState,
    CONN_RETRY_DELAY_MS, KEEPALIVE_INTERVAL_MS, MAX_CONN_RETRIES, MAX_CONN_RETRY_WINDOW_MS,
    PRICE_REPORT_INTERVAL_MS,
};

use super::{errors::ExchangeConnectionError, worker::PriceReporterConfig};

/// The price reporter handles opening connections to exchanges, and computing
/// price reports from the exchange data
#[derive(Clone, Debug)]
pub struct Reporter {
    /// The base Token (e.g., WETH)
    base_token: Token,
    /// The quote Token (e.g., USDC)
    quote_token: Token,
    /// The shared memory map from exchange to most recent price
    /// and reporting timestamp
    exchange_info: AtomicPriceStreamState,
}

impl Reporter {
    // ----------------------
    // | External Interface |
    // ----------------------

    /// Creates a new Reporter.
    pub fn new(
        base_token: Token,
        quote_token: Token,
        config: PriceReporterConfig,
    ) -> Result<Self, ExchangeConnectionError> {
        // Get the supported exchanges for the token pair
        let supported_exchanges = get_supported_exchanges(&base_token, &quote_token, &config);
        if supported_exchanges.is_empty() {
            warn!("No supported exchanges for {base_token}-{quote_token}");
            return Err(ExchangeConnectionError::NoSupportedExchanges(base_token, quote_token));
        }

        // Create shared memory that the `ConnectionMuxer` will use to communicate with
        // the `Reporter`
        let shared_exchange_state =
            AtomicPriceStreamState::new_from_exchanges(&supported_exchanges);

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
                    error!("Error in ConnectionMuxer for {base_token}-{quote_token}: {e}");
                }
            }
        });

        // Spawn a thread to stream price reports
        let self_ = Self { base_token, quote_token, exchange_info: shared_exchange_state };

        let self_clone = self_.clone();
        tokio::spawn(async move { self_clone.price_streamer_loop(config.system_bus).await });

        Ok(self_)
    }

    /// Non-blocking report of the latest ReporterState for the price
    pub fn peek_price(&self) -> PriceReporterState {
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

    /// An execution loop that streams price reports to the system bus
    async fn price_streamer_loop(&self, system_bus: SystemBus<SystemBusMessage>) {
        let topic_name = price_report_topic_name(&self.base_token, &self.quote_token);

        loop {
            if system_bus.has_listeners(&topic_name) {
                if let PriceReporterState::Nominal(report) = self.get_state() {
                    system_bus.publish(topic_name.clone(), SystemBusMessage::PriceReport(report));
                }
            }

            tokio::time::sleep(Duration::from_millis(PRICE_REPORT_INTERVAL_MS)).await;
        }
    }

    /// Construct a price report from a given price
    fn price_report_from_price(&self, price: Price, local_timestamp: u64) -> PriceReport {
        PriceReport {
            base_token: self.base_token.clone(),
            quote_token: self.quote_token.clone(),
            price,
            local_timestamp,
        }
    }

    /// Get the current price for the given pair, converting
    /// through the most liquid stablecoin quote asset if appropriate.
    /// Checks if the price is too stale or deviates too much from the median
    /// across other exchanges.
    fn get_state(&self) -> PriceReporterState {
        // We don't currently support Unnamed pairs
        if !is_pair_named(&self.base_token, &self.quote_token) {
            return PriceReporterState::UnsupportedPair(
                self.base_token.clone(),
                self.quote_token.clone(),
            );
        }

        // Fetch the most recent price
        match self.exchange_info.read_price(&Exchange::Binance) {
            None => PriceReporterState::NotEnoughDataReported(0),
            Some((price, ts)) => {
                // Fetch the most recent prices from all other exchanges
                let exchange_prices = ALL_EXCHANGES
                    .iter()
                    .filter_map(|exchange| {
                        self.exchange_info
                            .read_price(exchange)
                            .map(|price_state| (*exchange, price_state))
                    })
                    .collect::<Vec<_>>();

                // Compute the state of the price reporter
                compute_price_reporter_state(
                    self.base_token.clone(),
                    self.quote_token.clone(),
                    price,
                    ts,
                    &exchange_prices,
                )
            },
        }
    }
}

// -------------------
// | ConnectionMuxer |
// -------------------

/// The connection muxer manages a set of websocket connections abstracted as
/// `ExchangeConnection`s. It is responsible for restarting connections that
/// fail, and communicating the latest price reports to the `Reporter` via
/// an atomic shared memory primitive
struct ConnectionMuxer {
    /// The base token that the managed connections are reporting on
    base_token: Token,
    /// The quote token that the managed connections are reporting on
    quote_token: Token,
    /// The config for the price reporter
    config: PriceReporterConfig,
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
        config: PriceReporterConfig,
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
                            error!("Error sending keepalive to exchange: {e}");
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
                            },

                            Err(e) => {
                                // Restart the connection
                                error!("Error streaming from {exchange}: {e}, restarting connection...");
                                loop {
                                    match self.retry_connection(exchange).await {
                                        Ok(conn) => {
                                            info!("Successfully reconnected to {exchange}");
                                            stream_map.insert(exchange, conn);
                                        }
                                        Err(ExchangeConnectionError::MaxRetries(_)) => {
                                            error!("Max retries ({MAX_CONN_RETRIES}) exceeded, unable to connect to {exchange}... removing from data sources");
                                            stream_map.remove(&exchange);
                                            break;
                                        }
                                        _ => {
                                            warn!("Connection retry attempt failed");
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
                let config = self.config.exchange_conn_config.clone();

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
        info!("Retrying connection to {exchange}");
        connect_exchange(
            &self.base_token,
            &self.quote_token,
            &self.config.exchange_conn_config,
            exchange,
        )
        .await
    }
}
