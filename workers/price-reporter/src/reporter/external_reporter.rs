//! Utilities for streaming prices from an external reporter

use std::{str::FromStr, time::Duration};

use common::types::{exchange::Exchange, token::Token, Price};
use external_api::websocket::{SubscriptionResponse, WebsocketMessage};
use futures::{stream::SplitStream, SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tracing::{error, info};
use tungstenite::Message;
use url::Url;
use util::err_str;

use crate::{errors::ExchangeConnectionError, exchange::connection::ws_connect};

use super::{ConnectionMuxer, CONN_RETRY_DELAY_MS};

/// The error message for an invalid topic
const INVALID_TOPIC_ERR: &str = "Invalid topic";

/// A type alias for the read end of a websocket connection
type WebsocketReadStream = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

/// A message that is sent by the price reporter to the client indicating
/// a price udpate for the given topic
///
/// Ported over from https://github.com/renegade-fi/renegade-price-reporter/blob/main/src/utils.rs
#[derive(Serialize, Deserialize)]
pub struct PriceMessage {
    /// The topic for which the price update is being sent
    pub topic: String,
    /// The new price
    pub price: Price,
}

/// Stream prices from the external price reporter
pub async fn stream_from_external_reporter(
    connection_muxer: &ConnectionMuxer,
    price_reporter_url: &str,
) -> Result<(), ExchangeConnectionError> {
    // Package this into a connect + subscribe, return the read end
    // Connect to price reporter
    let url: Url = price_reporter_url.parse().expect("Invalid price reporter URL");

    // Listen for price updates & reconnect if needed
    loop {
        let mut read = connect_with_retries(url.clone(), connection_muxer).await?;

        loop {
            if let Some(res) = read.next().await {
                match res {
                    Ok(msg) => {
                        if let Message::Text(text) = msg {
                            // If receiving a subscription response from the price reporter,
                            // log the subscribed topics (exchange, base, quote)
                            if let Ok(subscription_response) =
                                serde_json::from_str::<SubscriptionResponse>(&text)
                            {
                                log_subscribed_exchanges(&subscription_response, connection_muxer)?;
                            }

                            // If receiving a price update from the price reporter, update the price
                            if let Ok(price_message) = serde_json::from_str::<PriceMessage>(&text) {
                                let exchange = parse_exchange_from_topic(&price_message.topic)?;
                                connection_muxer.update_price(exchange, price_message.price);
                            }
                        }
                    },
                    Err(e) => {
                        error!("Error streaming from external price reporter: {e}, restarting connection...");
                        break;
                    },
                }
            }
        }
    }
}

/// Attempt to reconnect to the external price reporter,
/// retrying indefinitely until a successful connection is made
async fn connect_with_retries(
    price_reporter_url: Url,
    connection_muxer: &ConnectionMuxer,
) -> Result<WebsocketReadStream, ExchangeConnectionError> {
    loop {
        match connect_and_subscribe(price_reporter_url.clone(), connection_muxer).await {
            Ok(read) => return Ok(read),
            Err(e) => {
                error!("Error connecting to external price reporter: {e}, retrying...");
                tokio::time::sleep(Duration::from_millis(CONN_RETRY_DELAY_MS)).await;
            },
        }
    }
}

/// Connect to the external price reporter and subscribe to the topics
/// for the given connection muxer
async fn connect_and_subscribe(
    price_reporter_url: Url,
    connection_muxer: &ConnectionMuxer,
) -> Result<WebsocketReadStream, ExchangeConnectionError> {
    let (mut write, read) = ws_connect(price_reporter_url).await?;

    // Subscribe to price updates for the pair across all exchanges
    for exchange in &connection_muxer.exchanges {
        write
            .send(Message::Text(
                serde_json::to_string(&WebsocketMessage::Subscribe {
                    topic: format_topic(
                        exchange,
                        &connection_muxer.base_token,
                        &connection_muxer.quote_token,
                    ),
                })
                .expect("Failed to serialize price reporter subscription"),
            ))
            .await
            .map_err(err_str!(ExchangeConnectionError::SendError))?;
    }

    Ok(read)
}

/// Format the topic for the given exchange and token pair
fn format_topic(exchange: &Exchange, base_token: &Token, quote_token: &Token) -> String {
    format!("{}-{}-{}", exchange, base_token, quote_token)
}

/// Parse the exchange from a given topic
fn parse_exchange_from_topic(topic: &str) -> Result<Exchange, ExchangeConnectionError> {
    let exchange = topic
        .split('-')
        .next()
        .ok_or(ExchangeConnectionError::InvalidMessage(INVALID_TOPIC_ERR.to_string()))?;

    Exchange::from_str(exchange)
        .map_err(|_| ExchangeConnectionError::InvalidMessage(INVALID_TOPIC_ERR.to_string()))
}

/// Log the exchanges that the price reporter has subscribed to
fn log_subscribed_exchanges(
    subscription_response: &SubscriptionResponse,
    connection_muxer: &ConnectionMuxer,
) -> Result<(), ExchangeConnectionError> {
    let exchanges = subscription_response
        .subscriptions
        .iter()
        .map(|t| parse_exchange_from_topic(t))
        .map(|res| res.map(|e| e.to_string()))
        .collect::<Result<Vec<String>, ExchangeConnectionError>>()?;

    info!(
        "Now subscribed to {}-{} pair on {} from external price reporter",
        connection_muxer.base_token,
        connection_muxer.quote_token,
        exchanges.join(", ")
    );

    Ok(())
}
