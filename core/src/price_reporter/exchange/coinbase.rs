//! Defines handler logic for a Coinbase websocket connection

use std::{
    collections::HashMap,
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use chrono::DateTime;
use futures_util::{SinkExt, Stream, StreamExt, Sink};
use hmac_sha256::HMAC;
use serde_json::{json};
use tracing::log;
use tungstenite::{Message, Error as WsError};
use url::Url;

use crate::{price_reporter::{
    errors::ExchangeConnectionError,
    exchange::{get_current_time, connection::ws_connect, InitializablePriceStream},
    reporter::{Price},
    tokens::Token,
    worker::PriceReporterManagerConfig,
}, state::{AsyncShared, new_async_shared}};

use super::{connection::{ExchangeConnection, parse_json_from_message, parse_json_field}, Exchange};

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
/// The name of the timestamp field on a coinbase event
const COINBASE_TIMESTAMP: &str = "timestamp";

/// The bid side field value
const COINBASE_BID: &str = "bid";
/// The offer side field value
const COINBASE_OFFER: &str = "offer";

// ----------------------
// | Connection Handler |
// ----------------------

/// The message handler for Exchange::Coinbase.
pub struct CoinbaseConnection {
    /// The order book information for the asset pair
    order_book: AsyncShared<CoinbaseOrderBookData>,
    /// The underlying stream of prices from the websocket
    price_stream: Box<dyn Stream<Item = Price> + Unpin>,
    /// The underlying write stream of the websocket
    write_stream: Box<dyn Sink<Message, Error = WsError>>,
}

/// The order book data stored locally by the connection
#[derive(Clone, Debug, Default)]
pub struct CoinbaseOrderBookData {
    // Note: The reason we use String's for price_level is because using f32 as a key produces
    // collision issues.
    /// A HashMap representing the local mirroring of Coinbase's order book bids.
    order_book_bids: HashMap<String, f32>,
    /// A HashMap representing the local mirroring of Coinbase's order book offers.
    order_book_offers: HashMap<String, f32>,
}

impl Stream for CoinbaseConnection {
    type Item = Price;

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
        let timestamp = (get_current_time() / 1000).to_string();
        let signature_bytes = HMAC::mac(
            format!("{}{}{}", timestamp, channel, product_ids),
            api_secret,
        );

        let signature = hex::encode(signature_bytes);
        json!({
            "type": "subscribe",
            "product_ids": [ product_ids ],
            "channels": [ channel ],
            "api_key": api_key,
            "timestamp": timestamp,
            "signature": signature,
        })
        .to_string()
    }

    /// Parse a midpoint price from a websocket message
    async fn midpoint_from_ws_message(
        order_book_data: AsyncShared<CoinbaseOrderBookData>,
        message: Message,
    ) -> Result<Option<Price>, ExchangeConnectionError> {
        // The json body of the message
        let json_blob = parse_json_from_message(message)?;
        if json_blob.is_none() {
            return Ok(None)
        }
        let json_blob = json_blob.unwrap();

        // Extract the list of events and update the order book
        let update_events = 
            if let Some(coinbase_events) = json_blob[COINBASE_EVENTS].as_array() 
            && let Some(update_events) = coinbase_events[0][COINBASE_EVENT_UPDATE].as_array() 
        {
            update_events
        } else {
            return Ok(None);
        };

        // Make updates to the locally replicated book given the price level updates
        let locked_bids = &mut order_book_data.write().await.order_book_bids;
        let locked_offers = &mut order_book_data.write().await.order_book_offers;
        for coinbase_event in update_events {
            let price_level: String = parse_json_field( COINBASE_PRICE_LEVEL, coinbase_event)?;
            let new_quantity: f32 = parse_json_field(COINBASE_NEW_QUANTITY, coinbase_event)?;
            let side: String = parse_json_field(COINBASE_SIDE, coinbase_event)?;

            match &side[..] {
                COINBASE_BID => {
                    if new_quantity == 0.0 {
                        locked_bids.remove(&price_level);
                    } else {
                        locked_bids .insert(price_level.clone(), new_quantity);
                    }
                }
                COINBASE_OFFER => {
                    if new_quantity == 0.0 {
                        locked_offers.remove(&price_level);
                    } else {
                        locked_offers.insert(price_level.clone(), new_quantity);
                    }
                }
                _ => {
                    return Err(ExchangeConnectionError::InvalidMessage(side.to_string()));
                }
            }
        }

        // Given the new order book, compute the best bid and offer.
        let best_bid = locked_bids.keys()
            .map(|key| key.parse::<f64>().unwrap())
            .fold(0.0, f64::max);
        let best_offer = locked_offers.keys()
            .map(|key| key.parse::<f64>().unwrap())
            .fold(f64::INFINITY, f64::min);

        let timestamp_str: String = parse_json_field(COINBASE_TIMESTAMP, &json_blob)?;
        let _reported_timestamp = DateTime::parse_from_rfc3339(&timestamp_str)
            .map_err(|err| ExchangeConnectionError::InvalidMessage(err.to_string()))?
            .timestamp_millis();

        Ok(Some((best_bid + best_offer) / 2.))
    }

}

#[async_trait]
impl ExchangeConnection for CoinbaseConnection {
    async fn connect(
        base_token: Token,
        quote_token: Token,
        config: PriceReporterManagerConfig,
    ) -> Result<Self, ExchangeConnectionError> {
        // Build the base websocket connection
        let url = Self::websocket_url();
        let (mut writer, read) = ws_connect(url).await?;

        // Subscribe to the order book
        let api_key = config
            .coinbase_api_key
            .expect("Coinbase API key expected in config, found None");
        let api_secret = config
            .coinbase_api_secret
            .expect("Coinbase API secret expected in config, found None");

        // Construct the route
        let authenticated_subscribe_msg = Self::construct_subscribe_message(
            &base_token, &quote_token, &api_key, &api_secret);

        // Setup the topic subscription
        writer
            .send(Message::Text(authenticated_subscribe_msg))
            .await
            .map_err(|err| ExchangeConnectionError::ConnectionHangup(err.to_string()))?;

        // Map the stream to process midpoint prices
        let order_book_data = new_async_shared(CoinbaseOrderBookData::default());
        let order_book_clone = order_book_data.clone();
        let mapped_stream = read.filter_map(move |message| {
            let order_book_clone = order_book_clone.clone();
            async move {
                match message {
                    Ok(msg) => match Self::midpoint_from_ws_message(order_book_clone, msg).await {
                        Ok(val) => val,
                        Err(e) => {
                            log::error!("Error parsing message from Coinbase: {e}");
                            None
                        }
                    },
                    Err(e) => { log::error!("Error reading message from Coinbase websocket: {e}"); None },
                }
            }
        });

        // Construct an initialized price stream from the initial price and the mapped stream
        let price_stream = InitializablePriceStream::new(
            Box::pin(mapped_stream),
        );

        Ok(Self {
            order_book: order_book_data,
            price_stream: Box::new(price_stream),
            write_stream: Box::new(writer),
        })
    }
}
