//! Defines handler logic for a Coinbase websocket connection

use std::{
    collections::HashMap,
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use common::types::{token::Token, Price};
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use hmac_sha256::HMAC;
use serde_json::json;
use tracing::error;
use tungstenite::{Error as WsError, Message};
use url::Url;
use util::get_current_time_seconds;

use crate::{errors::ExchangeConnectionError, worker::ExchangeConnectionsConfig};

use super::{
    connection::{
        parse_json_field, parse_json_from_message, ws_connect, ws_ping, ExchangeConnection,
    },
    Exchange, InitializablePriceStream, PriceStreamType,
};

// -------------
// | Constants |
// -------------

/// The name of the events field in a Coinbase WS message
const COINBASE_EVENTS: &str = "events";
/// The name of the updates field on a coinbase event
const COINBASE_EVENT_UPDATE: &str = "updates";
/// The name of the price level field on a coinbase event
const COINBASE_PRICE_LEVEL: &str = "price_level";
/// The name of the new quantity field on a coinbase event
const COINBASE_NEW_QUANTITY: &str = "new_quantity";
/// The name of the side field on a coinbase event
const COINBASE_SIDE: &str = "side";

/// The bid side field value
const COINBASE_BID: &str = "bid";
/// The offer side field value
const COINBASE_OFFER: &str = "offer";

// ----------------------
// | Connection Handler |
// ----------------------

/// The message handler for Exchange::Coinbase.
pub struct CoinbaseConnection {
    /// The underlying stream of prices from the websocket
    price_stream: Box<dyn Stream<Item = PriceStreamType> + Unpin + Send>,
    /// The underlying write stream of the websocket
    write_stream: Box<dyn Sink<Message, Error = WsError> + Unpin + Send>,
}

/// The order book data stored locally by the connection
#[derive(Clone, Debug, Default)]
pub struct CoinbaseOrderBookData {
    // Note: The reason we use String's for price_level is because using f32 as a key produces
    // collision issues
    /// A HashMap representing the local mirroring of Coinbase's order book
    /// bids.
    bids: HashMap<String, f32>,
    /// A HashMap representing the local mirroring of Coinbase's order book
    /// offers.
    offers: HashMap<String, f32>,
}

impl Stream for CoinbaseConnection {
    type Item = PriceStreamType;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        this.price_stream.as_mut().poll_next_unpin(cx)
    }
}

impl CoinbaseConnection {
    /// Get the URL of the Coinbase websocket endpoint
    fn websocket_url() -> Url {
        String::from("wss://advanced-trade-ws.coinbase.com").parse().unwrap()
    }

    /// Construct the websocket subscription message with HMAC authentication
    fn construct_subscribe_message(
        base_token: &Token,
        quote_token: &Token,
        api_key: &str,
        api_secret: &str,
    ) -> String {
        let base_ticker = base_token.get_exchange_ticker(Exchange::Coinbase);
        let quote_ticker = quote_token.get_exchange_ticker(Exchange::Coinbase);
        let product_ids = format!("{}-{}", base_ticker, quote_ticker);

        // Authenticate the request with the API key
        let channel = "level2";
        let timestamp = get_current_time_seconds().to_string();
        let signature_bytes =
            HMAC::mac(format!("{}{}{}", timestamp, channel, product_ids), api_secret);

        let signature = hex::encode(signature_bytes);
        json!({
            "type": "subscribe",
            "product_ids": [ product_ids ],
            "channel": channel,
            "api_key": api_key,
            "timestamp": timestamp,
            "signature": signature,
        })
        .to_string()
    }

    /// Parse a midpoint price from a websocket message
    fn midpoint_from_ws_message(
        order_book: &mut CoinbaseOrderBookData,
        message: Message,
    ) -> Result<Option<Price>, ExchangeConnectionError> {
        // The json body of the message
        let json_blob = parse_json_from_message(message)?;
        if json_blob.is_none() {
            return Ok(None);
        }
        let json_blob = json_blob.unwrap();

        // Extract the list of events and update the order book
        let update_events = if let Some(coinbase_events) = json_blob[COINBASE_EVENTS].as_array()
            && let Some(update_events) = coinbase_events[0][COINBASE_EVENT_UPDATE].as_array()
        {
            update_events
        } else {
            return Ok(None);
        };

        // Make updates to the locally replicated book given the price level updates
        // let mut locked_book = order_book_data.write().await;
        for coinbase_event in update_events {
            let price_level: String = parse_json_field(COINBASE_PRICE_LEVEL, coinbase_event)?;
            let new_quantity: f32 = parse_json_field(COINBASE_NEW_QUANTITY, coinbase_event)?;
            let side: String = parse_json_field(COINBASE_SIDE, coinbase_event)?;

            match &side[..] {
                COINBASE_BID => {
                    if new_quantity == 0.0 {
                        order_book.bids.remove(&price_level);
                    } else {
                        order_book.bids.insert(price_level.clone(), new_quantity);
                    }
                },
                COINBASE_OFFER => {
                    if new_quantity == 0.0 {
                        order_book.offers.remove(&price_level);
                    } else {
                        order_book.offers.insert(price_level.clone(), new_quantity);
                    }
                },
                _ => {
                    return Err(ExchangeConnectionError::InvalidMessage(side.to_string()));
                },
            }
        }

        // Given the new order book, compute the best bid and offer
        let best_bid =
            order_book.bids.keys().map(|key| key.parse::<f64>().unwrap()).fold(0.0, f64::max);
        let best_offer = order_book
            .offers
            .keys()
            .map(|key| key.parse::<f64>().unwrap())
            .fold(f64::INFINITY, f64::min);

        // Do not let the best offer be infinite as this gives an infinite midpoint
        if best_offer == f64::INFINITY {
            return Ok(Some(0.));
        }

        Ok(Some((best_bid + best_offer) / 2.))
    }
}

#[async_trait]
impl ExchangeConnection for CoinbaseConnection {
    async fn connect(
        base_token: Token,
        quote_token: Token,
        config: &ExchangeConnectionsConfig,
    ) -> Result<Self, ExchangeConnectionError> {
        // Build the base websocket connection
        let url = Self::websocket_url();
        let (mut writer, read) = ws_connect(url).await?;

        // Subscribe to the order book
        let api_key = config
            .coinbase_api_key
            .clone()
            .expect("Coinbase API key expected in config, found None");
        let api_secret = config
            .coinbase_api_secret
            .clone()
            .expect("Coinbase API secret expected in config, found None");

        let authenticated_subscribe_msg =
            Self::construct_subscribe_message(&base_token, &quote_token, &api_key, &api_secret);

        // Setup the topic subscription
        writer
            .send(Message::Text(authenticated_subscribe_msg))
            .await
            .map_err(|err| ExchangeConnectionError::ConnectionHangup(err.to_string()))?;

        // Map the stream of Coinbase messages to one of midpoint prices
        let mapped_stream = read.filter_map(move |message| {
            let mut order_book = CoinbaseOrderBookData::default();
            async move {
                match message {
                    // The outer `Result` comes from reading from the ws stream, the inner `Result`
                    // comes from parsing the message
                    Ok(val) => {
                        let res = Self::midpoint_from_ws_message(&mut order_book, val);
                        res.transpose()
                    },

                    Err(e) => {
                        error!("Error reading message from Coinbase websocket: {e}");
                        Some(Err(ExchangeConnectionError::ConnectionHangup(e.to_string())))
                    },
                }
            }
        });

        // Construct an initialized price stream from the initial price and the mapped
        // stream
        let price_stream = InitializablePriceStream::new(Box::pin(mapped_stream));

        Ok(Self { price_stream: Box::new(price_stream), write_stream: Box::new(writer) })
    }

    async fn send_keepalive(&mut self) -> Result<(), ExchangeConnectionError> {
        // Send a ping message
        ws_ping(&mut self.write_stream).await
    }
}
