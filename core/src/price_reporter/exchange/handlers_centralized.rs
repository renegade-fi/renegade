//! Defines logic for streaming from centralized exchanges

use async_trait::async_trait;
use futures::SinkExt;
use serde_json::{self, json, Value};
use tokio::net::TcpStream;
use tokio_tungstenite::{tungstenite::Message, MaybeTlsStream, WebSocketStream};

use crate::price_reporter::worker::PriceReporterManagerConfig;

use super::super::{
    errors::ExchangeConnectionError, exchange::Exchange, reporter::PriceReport, tokens::Token,
};

/// WebSocket type for streams from all centralized exchanges.
type WebSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// The core trait that all centralized exchange handlers implement. This allows for creation of
/// stateful elements (e.g., a local order book), websocket URLs, pre-websocket-stream one-off
/// price reports, and handling of remote messages.
#[async_trait]
pub trait CentralizedExchangeHandler {
    /// Create a new Handler.
    fn new(base_token: Token, quote_token: Token, config: PriceReporterManagerConfig) -> Self;
    /// Get the websocket URL to connect to.
    fn websocket_url(&self) -> String;
    /// Certain exchanges report the most recent price immediately after subscribing to the
    /// websocket. If the exchange requires an initial request to get caught up with exchange
    /// state, we query that here.
    async fn pre_stream_price_report(
        &mut self,
    ) -> Result<Option<PriceReport>, ExchangeConnectionError>;
    /// Send any initial subscription messages to the websocket after it has been created.
    async fn websocket_subscribe(
        &self,
        socket: &mut WebSocket,
    ) -> Result<(), ExchangeConnectionError>;
    /// Handle an inbound message from the exchange by parsing it into a PriceReport and publishing
    /// the PriceReport into the ring buffer channel.
    fn handle_exchange_message(
        &mut self,
        message_json: Value,
    ) -> Result<Option<PriceReport>, ExchangeConnectionError>;
}

/// The message handler for Exchange::Kraken.
#[derive(Clone, Debug)]
pub struct KrakenHandler {
    /// The base Token (e.g., WETH).
    base_token: Token,
    /// The quote Token (e.g., USDC).
    quote_token: Token,
}
#[async_trait]
impl CentralizedExchangeHandler for KrakenHandler {
    fn new(base_token: Token, quote_token: Token, _: PriceReporterManagerConfig) -> Self {
        Self {
            base_token,
            quote_token,
        }
    }

    fn websocket_url(&self) -> String {
        String::from("wss://ws.kraken.com")
    }

    async fn pre_stream_price_report(
        &mut self,
    ) -> Result<Option<PriceReport>, ExchangeConnectionError> {
        Ok(None)
    }

    async fn websocket_subscribe(
        &self,
        socket: &mut WebSocket,
    ) -> Result<(), ExchangeConnectionError> {
        let base_ticker = self.base_token.get_exchange_ticker(Exchange::Kraken);
        let quote_ticker = self.quote_token.get_exchange_ticker(Exchange::Kraken);
        let pair = format!("{}/{}", base_ticker, quote_ticker);
        let subscribe_str = json!({
            "event": "subscribe",
            "pair": [ pair ],
            "subscription": {
                "name": "spread",
            },
        })
        .to_string();
        socket
            .send(Message::Text(subscribe_str))
            .await
            .map_err(|err| ExchangeConnectionError::ConnectionHangup(err.to_string()))?;
        Ok(())
    }

    fn handle_exchange_message(
        &mut self,
        message_json: Value,
    ) -> Result<Option<PriceReport>, ExchangeConnectionError> {
        // Kraken sends status update messages. Ignore these.
        if ["systemStatus", "subscriptionStatus", "heartbeat"]
            .contains(&message_json["event"].as_str().unwrap_or(""))
        {
            return Ok(None);
        }
        let best_bid = match &message_json[1][0] {
            Value::String(best_bid) => best_bid.parse::<f64>().unwrap(),
            _ => {
                return Err(ExchangeConnectionError::InvalidMessage(
                    message_json[1][0].to_string(),
                ));
            }
        };
        let best_offer = match &message_json[1][1] {
            Value::String(best_offer) => best_offer.parse::<f64>().unwrap(),
            _ => {
                return Err(ExchangeConnectionError::InvalidMessage(
                    message_json[1][1].to_string(),
                ));
            }
        };
        let reported_timestamp_seconds = match &message_json[1][2] {
            Value::String(reported_timestamp) => reported_timestamp.parse::<f32>().unwrap(),
            _ => {
                return Err(ExchangeConnectionError::InvalidMessage(
                    message_json[1][2].to_string(),
                ));
            }
        };
        Ok(Some(PriceReport {
            base_token: self.base_token.clone(),
            quote_token: self.quote_token.clone(),
            exchange: Some(Exchange::Kraken),
            midpoint_price: (best_bid + best_offer) / 2.0,
            reported_timestamp: Some((reported_timestamp_seconds * 1000.0) as u128),
            local_timestamp: Default::default(),
        }))
    }
}

/// The message handler for Exchange::Okx.
#[derive(Clone, Debug)]
pub struct OkxHandler {
    /// The base Token (e.g., WETH).
    base_token: Token,
    /// The quote Token (e.g., USDC).
    quote_token: Token,
}
#[async_trait]
impl CentralizedExchangeHandler for OkxHandler {
    fn new(base_token: Token, quote_token: Token, _: PriceReporterManagerConfig) -> Self {
        Self {
            base_token,
            quote_token,
        }
    }

    fn websocket_url(&self) -> String {
        String::from("wss://ws.okx.com:8443/ws/v5/public")
    }

    async fn pre_stream_price_report(
        &mut self,
    ) -> Result<Option<PriceReport>, ExchangeConnectionError> {
        Ok(None)
    }

    async fn websocket_subscribe(
        &self,
        socket: &mut WebSocket,
    ) -> Result<(), ExchangeConnectionError> {
        let base_ticker = self.base_token.get_exchange_ticker(Exchange::Okx);
        let quote_ticker = self.quote_token.get_exchange_ticker(Exchange::Okx);
        let pair = format!("{}-{}", base_ticker, quote_ticker);
        let subscribe_str = json!({
            "op": "subscribe",
            "args": [{
                "channel": "bbo-tbt",
                "instId": pair,
            }],
        })
        .to_string();
        socket
            .send(Message::Text(subscribe_str))
            .await
            .map_err(|err| ExchangeConnectionError::ConnectionHangup(err.to_string()))?;
        Ok(())
    }

    fn handle_exchange_message(
        &mut self,
        message_json: Value,
    ) -> Result<Option<PriceReport>, ExchangeConnectionError> {
        // Okx sends status update messages. Ignore these.
        if message_json["event"].as_str().unwrap_or("") == "subscribe" {
            return Ok(None);
        }
        let best_bid = match &message_json["data"][0]["bids"][0][0] {
            Value::String(best_bid) => best_bid.parse::<f64>().unwrap(),
            _ => {
                return Err(ExchangeConnectionError::InvalidMessage(
                    message_json.to_string(),
                ));
            }
        };
        let best_offer = match &message_json["data"][0]["asks"][0][0] {
            Value::String(best_offer) => best_offer.parse::<f64>().unwrap(),
            _ => {
                return Err(ExchangeConnectionError::InvalidMessage(
                    message_json.to_string(),
                ));
            }
        };
        let reported_timestamp_seconds = match &message_json["data"][0]["ts"] {
            Value::String(reported_timestamp) => reported_timestamp.parse::<f32>().unwrap(),
            _ => {
                return Err(ExchangeConnectionError::InvalidMessage(
                    message_json.to_string(),
                ));
            }
        };
        Ok(Some(PriceReport {
            base_token: self.base_token.clone(),
            quote_token: self.quote_token.clone(),
            exchange: Some(Exchange::Okx),
            midpoint_price: (best_bid + best_offer) / 2.0,
            reported_timestamp: Some((reported_timestamp_seconds * 1000.0) as u128),
            local_timestamp: Default::default(),
        }))
    }
}
