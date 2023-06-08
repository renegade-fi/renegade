//! Defines a connection handler for Okx websockets

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use serde_json::json;
use tracing::log;
use tungstenite::{Error as WsError, Message};
use url::Url;

use crate::price_reporter::{
    errors::ExchangeConnectionError, reporter::Price, tokens::Token,
    worker::PriceReporterManagerConfig,
};

use super::{
    connection::{
        parse_json_field, parse_json_field_array, parse_json_from_message, ws_connect,
        ExchangeConnection,
    },
    Exchange, InitializablePriceStream,
};

// -------------
// | Constants |
// -------------

/// The event name for Okx status updates
const OKX_EVENT: &str = "event";
/// The subscribe event in an Okx websocket message
const OKX_SUBSCRIBE_EVENT: &str = "subscribe";

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
    price_stream: Box<dyn Stream<Item = Price> + Unpin>,
    /// The underlying write stream of the websocket
    write_stream: Box<dyn Sink<Message, Error = WsError>>,
}

impl OkxConnection {
    /// Get the Okx websocket API URL
    fn websocket_url() -> Url {
        String::from("wss://ws.okx.com:8443/ws/v5/public")
            .parse()
            .expect("Failed to parse Okx websocket URL")
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
    type Item = Price;

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
        _config: PriceReporterManagerConfig,
    ) -> Result<Self, ExchangeConnectionError>
    where
        Self: Sized,
    {
        // Connect to the websocket
        let url = Self::websocket_url();
        let (mut write, read) = ws_connect(url).await?;

        // Map the stream to process midpoint prices
        let mapped_stream = read.filter_map(|message| async {
            match message.map(Self::midpoint_from_ws_message) {
                Ok(Ok(Some(midpoint))) => Some(midpoint),
                Ok(Ok(None)) => None,
                Ok(Err(e)) => {
                    log::error!("Error parsing message from Okx: {}", e);
                    None
                }
                Err(e) => {
                    log::error!("Error reading message from Okx ws: {}", e);
                    None
                }
            }
        });

        // Subscribe to the asset pair's bbo tick-by-tick stream
        let base_ticker = base_token.get_exchange_ticker(Exchange::Okx);
        let quote_ticker = quote_token.get_exchange_ticker(Exchange::Okx);
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

        // Build a price stream
        let price_stream = InitializablePriceStream::new(Box::pin(mapped_stream));
        Ok(Self {
            price_stream: Box::new(price_stream),
            write_stream: Box::new(write),
        })
    }
}
