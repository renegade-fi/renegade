//! Defines the Reporter, which is responsible for computing
//! PriceReports by managing individual ExchangeConnections in a fault-tolerant
//! manner.

use common::types::exchange::{Exchange, PriceReporterState};
use common::types::token::{default_exchange_stable, Token};
use common::types::Price;
use external_api::bus_message::{price_report_topic_name, SystemBusMessage};
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::Instant;
use tokio_stream::{StreamExt, StreamMap};
use tracing::{error, info, warn};
use util::{err_str, get_current_time_seconds};

use crate::exchange::connect_exchange;
use crate::exchange::connection::ExchangeConnection;
use crate::manager::{
    eligible_for_stable_quote_conversion, get_state, get_supported_exchanges,
    SharedPriceStreamStates, CONN_RETRY_DELAY_MS, KEEPALIVE_INTERVAL_MS, MAX_CONN_RETRIES,
    MAX_CONN_RETRY_WINDOW_MS, PRICE_REPORT_INTERVAL_MS,
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
    /// The latest states of all price streams from exchange connections
    price_stream_states: SharedPriceStreamStates,
    /// The configuration for the price reporter
    config: PriceReporterConfig,
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
        let price_stream_states = SharedPriceStreamStates::default();

        // Spawn a thread to manage the connections
        let connection_muxer = ConnectionMuxer::new(
            base_token.clone(),
            quote_token.clone(),
            config.clone(),
            supported_exchanges,
            price_stream_states.clone(),
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
        let self_ = Self { base_token, quote_token, price_stream_states, config };

        let self_clone = self_.clone();
        tokio::spawn(async move { self_clone.price_streamer_loop().await });

        Ok(self_)
    }

    /// Non-blocking report of the latest ReporterState for the price
    pub async fn peek_price(&self) -> PriceReporterState {
        get_state(
            &self.price_stream_states,
            self.base_token.clone(),
            self.quote_token.clone(),
            &self.config,
        )
        .await
    }

    // -----------
    // | Helpers |
    // -----------

    /// An execution loop that streams price reports to the system bus
    async fn price_streamer_loop(&self) {
        let topic_name = price_report_topic_name(&self.base_token, &self.quote_token);

        loop {
            if self.config.system_bus.has_listeners(&topic_name) {
                if let PriceReporterState::Nominal(report) = get_state(
                    &self.price_stream_states,
                    self.base_token.clone(),
                    self.quote_token.clone(),
                    &self.config,
                )
                .await
                {
                    self.config
                        .system_bus
                        .publish(topic_name.clone(), SystemBusMessage::PriceReport(report));
                }
            }

            tokio::time::sleep(Duration::from_millis(PRICE_REPORT_INTERVAL_MS)).await;
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
    price_stream_states: SharedPriceStreamStates,
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
        price_stream_states: SharedPriceStreamStates,
    ) -> Self {
        Self {
            base_token,
            quote_token,
            config,
            exchanges,
            price_stream_states,
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
                                self.price_stream_states
                                    .new_price(exchange, self.base_token.clone(), self.quote_token.clone(), price, ts).await.map_err(err_str!(ExchangeConnectionError::SaveState))?;
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
    // TODO(@akirillo): Conditionally start component price streams here
    async fn initialize_connections<'a>(
        &mut self,
    ) -> Result<StreamMap<Exchange, Box<dyn ExchangeConnection>>, ExchangeConnectionError> {
        // We do not use a more convenient stream here for concurrent init because of:
        //   https://github.com/rust-lang/rust/issues/102211
        // In specific, streams in async blocks sometimes have lifetimes erased which
        // makes it impossible for the compiler to infer auto-traits like `Send`

        let mut conns = Vec::new();
        for exchange in &self.exchanges {
            // If pair is eligible, we may invoke price conversion through the default
            // stable quote for the exchange
            if eligible_for_stable_quote_conversion(&self.base_token, &self.quote_token, exchange) {
                let default_stable = default_exchange_stable(exchange);

                // Connect to the price stream for the base / default stable pair
                conns.push(
                    connect_exchange(
                        &self.base_token,
                        &default_stable,
                        &self.config.exchange_conn_config,
                        *exchange,
                    )
                    .await?,
                );

                // Connect to the price stream for the quote / default stable
                // pair
                conns.push(
                    connect_exchange(
                        &self.quote_token,
                        &default_stable,
                        &self.config.exchange_conn_config,
                        *exchange,
                    )
                    .await?,
                );
            } else {
                // Connect directly to the price stream for the base / quote pair
                conns.push(
                    connect_exchange(
                        &self.base_token,
                        &self.quote_token,
                        &self.config.exchange_conn_config,
                        *exchange,
                    )
                    .await?,
                );
            }
        }

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
