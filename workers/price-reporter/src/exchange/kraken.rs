//! Defines an abstraction over a Kraken WS connection

use std::{
    collections::HashSet,
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use common::types::{exchange::Exchange, token::Token, Price};
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use lazy_static::lazy_static;
use serde_json::{json, Value};
use tracing::error;
use tungstenite::{Error as WsError, Message};
use url::Url;
use util::err_str;

use crate::{
    errors::ExchangeConnectionError, manager::exchange_lists_pair_tokens,
    worker::ExchangeConnectionsConfig,
};

use super::{
    connection::{
        parse_json_field_array, parse_json_from_message, ws_connect, ws_ping, ExchangeConnection,
    },
    InitializablePriceStream, PriceStreamType,
};

// -------------
// | Constants |
// -------------

/// The base URL for the Kraken websocket endpoint
const KRAKEN_WS_BASE_URL: &str = "wss://ws.kraken.com";
/// The base URL for the Kraken REST API
const KRAKEN_REST_BASE_URL: &str = "https://api.kraken.com/0/public";

/// The name of the events field in a Kraken WS message
const KRAKEN_EVENT: &str = "event";
/// The index of the price data in a Kraken WS message
const KRAKEN_PRICE_DATA_INDEX: usize = 1;
/// The index of the bid price in a Kraken WS message's price data
const KRAKEN_BID_PRICE_INDEX: usize = 0;
/// The index of the ask price in a Kraken WS message's price data
const KRAKEN_ASK_PRICE_INDEX: usize = 1;
/// The timestamp of the price report from kraken
const KRAKEN_PRICE_REPORT_TIMESTAMP_INDEX: usize = 2;
/// The name of the error field in a Kraken API response
const KRAKEN_ERROR: &str = "error";

lazy_static! {
    static ref KRAKEN_MSG_IGNORE_LIST: HashSet<String> = {
        let mut set = HashSet::new();

        set.insert(String::from("systemStatus"));
        set.insert(String::from("subscriptionStatus"));
        set.insert(String::from("heartbeat"));
        set
    };
}

// -----------------------------
// | Connection Implementation |
// -----------------------------

/// The message handler for Exchange::Kraken.
pub struct KrakenConnection {
    /// The underlying price stream
    price_stream: Box<dyn Stream<Item = PriceStreamType> + Unpin + Send>,
    /// The underlying write stream of the websocket
    write_stream: Box<dyn Sink<Message, Error = WsError> + Unpin + Send>,
}

impl KrakenConnection {
    /// Get the URL for the Kraken websocket endpoint
    fn websocket_url() -> Url {
        String::from(KRAKEN_WS_BASE_URL).parse().expect("Failed to parse Kraken websocket URL")
    }

    /// Parse a price report from a Kraken websocket message
    fn midpoint_from_ws_message(
        message: Message,
    ) -> Result<Option<Price>, ExchangeConnectionError> {
        // Parse the message to json
        let json_blob = parse_json_from_message(message)?;
        if json_blob.is_none() {
            return Ok(None);
        }
        let message_json = json_blob.unwrap();

        // Kraken sends status update messages. Ignore these.
        if KRAKEN_MSG_IGNORE_LIST
            .contains(&message_json[KRAKEN_EVENT].as_str().unwrap_or("").to_string())
        {
            return Ok(None);
        }

        let price_data = &message_json[KRAKEN_PRICE_DATA_INDEX];
        let best_bid: f64 = parse_json_field_array(KRAKEN_BID_PRICE_INDEX, price_data)?;
        let best_offer: f64 = parse_json_field_array(KRAKEN_ASK_PRICE_INDEX, price_data)?;
        let _reported_timestamp_seconds: f32 =
            parse_json_field_array(KRAKEN_PRICE_REPORT_TIMESTAMP_INDEX, price_data)?;

        Ok(Some((best_bid + best_offer) / 2.0))
    }
}

impl Stream for KrakenConnection {
    type Item = PriceStreamType;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        Pin::new(&mut this.price_stream).poll_next(cx)
    }
}

#[async_trait]
impl ExchangeConnection for KrakenConnection {
    async fn connect(
        base_token: Token,
        quote_token: Token,
        _config: &ExchangeConnectionsConfig,
    ) -> Result<Self, ExchangeConnectionError>
    where
        Self: Sized,
    {
        if !Self::supports_pair(&base_token, &quote_token).await? {
            return Err(ExchangeConnectionError::UnsupportedPair(
                base_token,
                quote_token,
                Exchange::Kraken,
            ));
        }

        // Connect to the websocket
        let url = Self::websocket_url();
        let (mut write, read) = ws_connect(url).await?;

        // Subscribe to the asset pair spread topic
        let base_ticker = base_token.get_exchange_ticker(Exchange::Kraken);
        let quote_ticker = quote_token.get_exchange_ticker(Exchange::Kraken);
        let pair = format!("{}/{}", base_ticker, quote_ticker);
        let subscribe_str = json!({
            "event": "subscribe",
            "pair": [ pair ],
            "subscription": {
                "name": "spread",
            },
        })
        .to_string();

        write
            .send(Message::Text(subscribe_str))
            .await
            .map_err(|err| ExchangeConnectionError::ConnectionHangup(err.to_string()))?;

        // Map the stream to process midpoint prices
        let mapped_stream = read.filter_map(|message| async {
            match message.map(Self::midpoint_from_ws_message) {
                // The outer `Result` comes from reading the websocket stream
                // Processing the stream messages returns a `Result<Option<..>>` which we
                // flip via `transpose`
                Ok(val) => val.transpose(),

                // Error reading from the websocket
                Err(e) => {
                    error!("Error reading message from Kraken ws: {}", e);
                    Some(Err(ExchangeConnectionError::ConnectionHangup(e.to_string())))
                },
            }
        });

        // Build a price stream
        let price_stream = InitializablePriceStream::new(Box::pin(mapped_stream));
        Ok(Self { price_stream: Box::new(price_stream), write_stream: Box::new(write) })
    }

    async fn send_keepalive(&mut self) -> Result<(), ExchangeConnectionError> {
        ws_ping(&mut self.write_stream).await
    }

    async fn supports_pair(
        base_token: &Token,
        quote_token: &Token,
    ) -> Result<bool, ExchangeConnectionError> {
        if !exchange_lists_pair_tokens(Exchange::Kraken, base_token, quote_token) {
            return Ok(false);
        }

        let base_ticker = base_token.get_exchange_ticker(Exchange::Kraken);
        let quote_ticker = quote_token.get_exchange_ticker(Exchange::Kraken);
        let pair = format!("{}/{}", base_ticker, quote_ticker);

        // Query the `AssetPairs` endpoint about the pair
        let request_url = format!("{KRAKEN_REST_BASE_URL}/AssetPairs?pair={pair}");

        let response = reqwest::get(request_url)
            .await
            .map_err(err_str!(ExchangeConnectionError::ConnectionHangup))?;

        let res_json: Value =
            response.json().await.map_err(err_str!(ExchangeConnectionError::InvalidMessage))?;

        match &res_json[KRAKEN_ERROR] {
            // No errors => Kraken supports the pair
            Value::Array(errors) => Ok(errors.is_empty()),
            _ => Err(ExchangeConnectionError::InvalidMessage(
                "Invalid response from Kraken".to_string(),
            )),
        }
    }
}
