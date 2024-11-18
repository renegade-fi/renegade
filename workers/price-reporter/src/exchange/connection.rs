//! Defines abstract connection interfaces that can be streamed from

use async_trait::async_trait;
use common::types::{exchange::Exchange, token::Token, Price};
use futures::stream::StreamExt;
use futures_util::{
    stream::{SplitSink, SplitStream},
    Sink, SinkExt, Stream,
};
use serde_json::Value;
use std::{str::FromStr, time::Duration};
use tokio::{net::TcpStream, time::Instant};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use tracing::{error, info, warn};
use tungstenite::Error as WsError;
use url::Url;
use util::{err_str, get_current_time_millis};

use crate::{
    manager::{
        SharedPriceStreamStates, CONN_RETRY_DELAY_MS, KEEPALIVE_INTERVAL_MS, MAX_CONN_RETRIES,
        MAX_CONN_RETRY_WINDOW_MS,
    },
    worker::{ExchangeConnectionsConfig, PriceReporterConfig},
};

use super::{super::errors::ExchangeConnectionError, connect_exchange, PriceStreamType};

// -------------
// | Constants |
// -------------

/// The message passed when Okx observes a protocol violation
const PROTOCOL_VIOLATION_MSG: &str = "Protocol violation";
/// The message Okx passes in response to a keepalive ping
const PONG_MESSAGE: &str = "pong";
/// The message passed when a ws proxy resets
const CLOUDFLARE_RESET_MESSAGE: &str = "CloudFlare WebSocket proxy restarting";

// -----------
// | Helpers |
// -----------

/// Build a websocket connection to the given endpoint
pub(crate) async fn ws_connect(
    url: Url,
) -> Result<
    (
        SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
        SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    ),
    ExchangeConnectionError,
> {
    let ws_conn = match connect_async(url.clone()).await {
        Ok((conn, _resp)) => conn,
        Err(e) => {
            error!("Cannot connect to the remote URL: {}", url);
            return Err(ExchangeConnectionError::HandshakeFailure(e.to_string()));
        },
    };

    let (ws_sink, ws_stream) = ws_conn.split();
    Ok((ws_sink, ws_stream))
}

/// Send a default ping message on the websocket
pub(super) async fn ws_ping<S: Sink<Message, Error = WsError> + Unpin>(
    ws_sink: &mut S,
) -> Result<(), ExchangeConnectionError> {
    ws_sink
        .send(Message::Ping(vec![]))
        .await
        .map_err(|e| ExchangeConnectionError::SendError(e.to_string()))
}

/// Helper to parse a value from a JSON response
pub(super) fn parse_json_field<T: FromStr>(
    field_name: &str,
    response: &Value,
) -> Result<T, ExchangeConnectionError> {
    match response[field_name].as_str() {
        None => Err(ExchangeConnectionError::InvalidMessage(response.to_string())),
        Some(field_value) => field_value
            .parse()
            .map_err(|_| ExchangeConnectionError::InvalidMessage(response.to_string())),
    }
}

/// Helper to parse a value from a JSON response by index
pub(super) fn parse_json_field_array<T: FromStr>(
    field_index: usize,
    response: &Value,
) -> Result<T, ExchangeConnectionError> {
    match response[field_index].as_str() {
        None => Err(ExchangeConnectionError::InvalidMessage(response.to_string())),
        Some(field_value) => field_value
            .parse()
            .map_err(|_| ExchangeConnectionError::InvalidMessage(response.to_string())),
    }
}

/// Parse an json structure from a websocket message
pub fn parse_json_from_message(message: Message) -> Result<Option<Value>, ExchangeConnectionError> {
    if let Message::Text(message_str) = message {
        // Okx sends some undocumented messages: Empty strings and "Protocol violation"
        // messages
        if message_str == PROTOCOL_VIOLATION_MSG || message_str.is_empty() {
            return Ok(None);
        }

        // Okx sends "pong" messages from our "ping" messages
        if message_str == PONG_MESSAGE {
            return Ok(None);
        }

        // Okx and Kraken send "CloudFlare WebSocket proxy restarting" messages
        if message_str == CLOUDFLARE_RESET_MESSAGE {
            return Ok(None);
        }

        // Parse into a json blob
        serde_json::from_str(&message_str).map_err(|err| {
            ExchangeConnectionError::InvalidMessage(format!("{} for message: {}", err, message_str))
        })
    } else {
        Ok(None)
    }
}

// --------------------------
// | Connection Abstraction |
// --------------------------

/// A trait representing a connection to an exchange
#[async_trait]
pub trait ExchangeConnection: Stream<Item = PriceStreamType> + Unpin + Send {
    /// Create a new connection to the exchange on a given asset pair
    async fn connect(
        base_token: Token,
        quote_token: Token,
        config: &ExchangeConnectionsConfig,
    ) -> Result<Self, ExchangeConnectionError>
    where
        Self: Sized;

    /// Send a keepalive signal on the connection if necessary
    async fn send_keepalive(&mut self) -> Result<(), ExchangeConnectionError> {
        Ok(())
    }

    /// Check whether the exchange supports the given pair
    async fn supports_pair(
        base_token: &Token,
        quote_token: &Token,
    ) -> Result<bool, ExchangeConnectionError>
    where
        Self: Sized;
}

// -----------------------------
// | ExchangeConnectionManager |
// -----------------------------

/// Manages a websocket connection abstracted as an `ExchangeConnection`.
/// It is responsible for restarting the connection if it fails, and updating
/// prices in the shared price stream states map.
pub struct ExchangeConnectionManager {
    /// The exchange to which the manager is connected
    exchange: Exchange,
    /// The base token that the managed connections are reporting on
    base_token: Token,
    /// The quote token that the managed connections are reporting on
    quote_token: Token,
    /// The config for the price reporter
    config: PriceReporterConfig,
    /// The shared memory map from exchange to most recent price
    price_stream_states: SharedPriceStreamStates,
    /// Tracks the number of failures within the last `MAX_CONN_RETRY_WINDOW_MS`
    /// milliseconds in connecting to the exchange
    retries: Vec<Instant>,
}

impl ExchangeConnectionManager {
    /// Create a new `ExchangeConnectionManager`
    pub fn new(
        exchange: Exchange,
        base_token: Token,
        quote_token: Token,
        config: PriceReporterConfig,
        price_stream_states: SharedPriceStreamStates,
    ) -> Self {
        Self { exchange, base_token, quote_token, config, price_stream_states, retries: Vec::new() }
    }

    /// Start the exchange connection manager
    pub async fn execution_loop(self) -> Result<(), ExchangeConnectionError> {
        // Start a keepalive timer
        let delay = tokio::time::sleep(Duration::from_millis(KEEPALIVE_INTERVAL_MS));
        tokio::pin!(delay);

        // Connect to the (exchange, base, quote)
        let mut connection = self.initialize_connection().await?;

        loop {
            tokio::select! {
                // Keepalive timer
                _ = &mut delay => {
                    if let Err(e) = connection.send_keepalive().await {
                        error!("Error sending keepalive to exchange: {e}");
                    }

                    delay.as_mut().reset(Instant::now() + Duration::from_millis(KEEPALIVE_INTERVAL_MS));
                },

                // New price streamed from an exchange
                stream_elem = connection.next() => {
                    if let Some(res) = stream_elem {
                        match res {
                            Ok(price) => {
                                self.handle_new_price(price).await?;
                            },

                            Err(e) => {
                                self.handle_connection_error(e, &mut connection).await;
                            }

                        }
                    }
                }
            }
        }
    }

    /// Handles a new price from the exchange connection, updating the price
    /// stream's state in the global map
    async fn handle_new_price(&self, price: Price) -> Result<(), ExchangeConnectionError> {
        // Do not update if the price is default, simply let the price age
        if price == Price::default() {
            return Ok(());
        }

        // Save the price update to the global map
        let ts = get_current_time_millis();
        self.price_stream_states
            .new_price(self.exchange, self.base_token.clone(), self.quote_token.clone(), price, ts)
            .await
            .map_err(err_str!(ExchangeConnectionError::SaveState))?;

        // Compute the high-level price report for the pair and publish to the system
        // bus
        self.price_stream_states
            .publish_price_report(self.base_token.clone(), self.quote_token.clone(), &self.config)
            .await;

        Ok(())
    }

    /// Handles an error streaming through the exchange connection, attempting
    /// to reconnect until retry attempts are exhausted
    async fn handle_connection_error(
        &self,
        e: ExchangeConnectionError,
        connection: &mut Box<dyn ExchangeConnection>,
    ) {
        // Restart the connection
        error!("Error streaming from {}: {e}, restarting connection...", self.exchange);
        loop {
            match self.retry_connection().await {
                Ok(conn) => {
                    info!("Successfully reconnected to {}", self.exchange);
                    *connection = conn;
                    // The stream's state must have already been initialized in
                    // `self.price_stream_states`,
                    // so we do not need to re-add it here
                },
                Err(ExchangeConnectionError::MaxRetries(_)) => {
                    error!(
                        "Max retries ({MAX_CONN_RETRIES}) exceeded, unable to connect to {}... removing from data sources",
                        self.exchange,
                    );
                    self.price_stream_states
                        .remove_state(
                            self.exchange,
                            self.base_token.clone(),
                            self.quote_token.clone(),
                        )
                        .await;
                    break;
                },
                _ => {
                    warn!("Connection retry attempt failed");
                },
            }
        }
    }

    /// Initializes a connection for the given exchange and token pair,
    /// initializing a state for it in the global price stream states map.
    async fn initialize_connection(
        &self,
    ) -> Result<Box<dyn ExchangeConnection>, ExchangeConnectionError> {
        if self
            .price_stream_states
            .state_is_initialized(self.exchange, self.base_token.clone(), self.quote_token.clone())
            .await
        {
            return Err(ExchangeConnectionError::AlreadyInitialized(
                self.exchange,
                self.base_token.clone(),
                self.quote_token.clone(),
            ));
        }

        self.price_stream_states
            .initialize_state(self.exchange, self.base_token.clone(), self.quote_token.clone())
            .await;

        connect_exchange(
            &self.base_token,
            &self.quote_token,
            &self.config.exchange_conn_config,
            self.exchange,
        )
        .await
    }

    /// Retries an exchange connection after it has failed
    async fn retry_connection(
        &self,
    ) -> Result<Box<dyn ExchangeConnection>, ExchangeConnectionError> {
        // Increment the retry count and filter out old requests
        let now = Instant::now();
        let mut retry_timestamps = self.retries.clone();
        retry_timestamps
            .retain(|ts| now.duration_since(*ts) < Duration::from_millis(MAX_CONN_RETRY_WINDOW_MS));

        // Add the current timestamp to the set of retries
        retry_timestamps.push(now);

        if retry_timestamps.len() >= MAX_CONN_RETRIES {
            return Err(ExchangeConnectionError::MaxRetries(self.exchange));
        }

        // Add delay before retrying
        tokio::time::sleep(Duration::from_secs(CONN_RETRY_DELAY_MS)).await;

        // Reconnect
        info!("Retrying connection to {}", self.exchange);
        connect_exchange(
            &self.base_token,
            &self.quote_token,
            &self.config.exchange_conn_config,
            self.exchange,
        )
        .await
    }
}
