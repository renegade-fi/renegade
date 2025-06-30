//! Defines a connection handler for Okx websockets

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use common::types::{price::Price, token::Token};
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use serde_json::{Value, json};
use tracing::error;
use tungstenite::{Error as WsError, Message};
use url::Url;
use util::err_str;

use crate::{
    errors::ExchangeConnectionError, manager::exchange_lists_pair_tokens,
    worker::ExchangeConnectionsConfig,
};

use super::{
    Exchange, InitializablePriceStream, PriceStreamType,
    connection::{
        ExchangeConnection, parse_json_field, parse_json_field_array, parse_json_from_message,
        ws_connect,
    },
    get_base_exchange_ticker, get_quote_exchange_ticker,
};

// -------------
// | Constants |
// -------------

/// The base URL for the Okx websocket endpoint
const OKX_WS_BASE_URL: &str = "wss://ws.okx.com:8443/ws/v5/public";
/// The base URL for the Okx REST API
const OKX_REST_BASE_URL: &str = "https://okx.com/api/v5/public";

/// The event name for Okx status updates
const OKX_EVENT: &str = "event";
/// The subscribe event in an Okx websocket message
const OKX_SUBSCRIBE_EVENT: &str = "subscribe";
/// The ping message body used to keep the connection alive
const OKX_PING_MESSAGE: &str = "ping";

/// The field name for response data on an Okx websocket message
///
/// TODO: Possibly refactor into a serde-compatible struct
const OKX_DATA: &str = "data";
/// The field name for bids on an Okx bbo websocket message
const OKX_BIDS: &str = "bids";
/// The field name for asks on an Okx bbo websocket message
const OKX_ASKS: &str = "asks";
/// the field name for the timestamp on an Okx websocket message
const OKX_TIMESTAMP: &str = "ts";
/// The data index to pull the first bid or ask
const FIRST_ENTRY: usize = 0;
/// The data index to pull the price from a bid or ask
const OKX_PRICE: usize = 0;

// -----------------------------
// | Connection Implementation |
// -----------------------------

/// The message handler for Exchange::Okx.
pub struct OkxConnection {
    /// The underlying price stream
    price_stream: Box<dyn Stream<Item = PriceStreamType> + Unpin + Send>,
    /// The underlying write stream of the websocket
    write_stream: Box<dyn Sink<Message, Error = WsError> + Unpin + Send>,
}

impl OkxConnection {
    /// Get the Okx websocket API URL
    fn websocket_url() -> Url {
        String::from(OKX_WS_BASE_URL).parse().expect("Failed to parse Okx websocket URL")
    }

    /// Parse a price from an Okx websocket message
    fn midpoint_from_ws_message(
        message: Message,
    ) -> Result<Option<Price>, ExchangeConnectionError> {
        let json_blob = parse_json_from_message(message)?;
        if json_blob.is_none() {
            return Ok(None);
        }
        let message_json = json_blob.unwrap();

        // Ignore Okx status update messages
        if message_json[OKX_EVENT].as_str().unwrap_or("") == OKX_SUBSCRIBE_EVENT {
            return Ok(None);
        }

        // Parse fields from the response
        let first_data_entry = &message_json[OKX_DATA][FIRST_ENTRY];
        let best_bid: f64 =
            parse_json_field_array(OKX_PRICE, &first_data_entry[OKX_BIDS][FIRST_ENTRY])?;
        let best_offer: f64 =
            parse_json_field_array(OKX_PRICE, &first_data_entry[OKX_ASKS][FIRST_ENTRY])?;
        let _reported_timestamp_seconds: f32 = parse_json_field(OKX_TIMESTAMP, first_data_entry)?;

        Ok(Some((best_bid + best_offer) / 2.0))
    }
}

impl Stream for OkxConnection {
    type Item = PriceStreamType;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        Pin::new(&mut this.price_stream).poll_next(cx)
    }
}

#[async_trait]
impl ExchangeConnection for OkxConnection {
    async fn connect(
        base_token: Token,
        quote_token: Token,
        _config: &ExchangeConnectionsConfig,
    ) -> Result<Self, ExchangeConnectionError>
    where
        Self: Sized,
    {
        // Connect to the websocket
        let url = Self::websocket_url();
        let (mut write, read) = ws_connect(url).await?;

        // Subscribe to the asset pair's bbo tick-by-tick stream
        let base_ticker =
            get_base_exchange_ticker(base_token.clone(), quote_token.clone(), Exchange::Okx)?;
        let quote_ticker =
            get_quote_exchange_ticker(base_token.clone(), quote_token.clone(), Exchange::Okx)?;

        let pair = format!("{}-{}", base_ticker, quote_ticker);
        let subscribe_str = json!({
            "op": "subscribe",
            "args": [{
                "channel": "bbo-tbt",
                "instId": pair,
            }],
        })
        .to_string();

        write
            .send(Message::Text(subscribe_str))
            .await
            .map_err(|err| ExchangeConnectionError::ConnectionHangup(err.to_string()))?;

        // Map the stream to process midpoint prices
        let mapped_stream = read.filter_map(|message| async {
            match message.map(Self::midpoint_from_ws_message) {
                // The outer `Result` comes from reading the message from the websocket
                // Processing the message returns a `Result<Option<..>>` which we
                // flip to match the stream type
                Ok(mapped_res) => mapped_res.transpose(),

                // Error reading from the websocket
                Err(e) => {
                    error!("Error reading message from Okx ws: {}", e);
                    Some(Err(ExchangeConnectionError::ConnectionHangup(e.to_string())))
                },
            }
        });

        // Build a price stream
        let price_stream = InitializablePriceStream::new(Box::pin(mapped_stream));
        Ok(Self { price_stream: Box::new(price_stream), write_stream: Box::new(write) })
    }

    async fn send_keepalive(&mut self) -> Result<(), ExchangeConnectionError> {
        // Okx in specific uses a text representation of the ping message
        self.write_stream
            .send(Message::Text(String::from(OKX_PING_MESSAGE)))
            .await
            .map_err(|err| ExchangeConnectionError::ConnectionHangup(err.to_string()))
    }

    async fn supports_pair(
        base_token: &Token,
        quote_token: &Token,
    ) -> Result<bool, ExchangeConnectionError> {
        if !exchange_lists_pair_tokens(Exchange::Okx, base_token, quote_token) {
            return Ok(false);
        }

        let base_ticker = match base_token.get_exchange_ticker(Exchange::Okx) {
            Some(ticker) => ticker,
            None => return Ok(false),
        };
        let quote_ticker = match quote_token.get_exchange_ticker(Exchange::Okx) {
            Some(ticker) => ticker,
            None => return Ok(false),
        };

        let instrument = format!("{}-{}", base_ticker, quote_ticker);

        // Query the `instruments` endpoint about the pair
        let request_url =
            format!("{OKX_REST_BASE_URL}/instruments?instType=SPOT&instId={instrument}");

        let response = reqwest::get(request_url)
            .await
            .map_err(err_str!(ExchangeConnectionError::ConnectionHangup))?;

        let res_json: Value =
            response.json().await.map_err(err_str!(ExchangeConnectionError::InvalidMessage))?;

        match &res_json[OKX_DATA] {
            // Data is non-empty => Okx supports the pair
            Value::Array(data) => Ok(!data.is_empty()),
            _ => Err(ExchangeConnectionError::InvalidMessage(
                "Invalid response from Okx".to_string(),
            )),
        }
    }
}
