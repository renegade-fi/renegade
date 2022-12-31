use chrono::DateTime;
use futures::executor::block_on;
use hmac_sha256::HMAC;
use serde_json::{self, json, Value};
use std::{collections::HashMap, env, net::TcpStream};
use tungstenite::{stream::MaybeTlsStream, Message, WebSocket as WebSocketGeneric};

use crate::{
    errors::ReporterError,
    exchanges::{connection::get_current_time, Exchange},
    reporter::PriceReport,
    tokens::Token,
};

type WebSocket = WebSocketGeneric<MaybeTlsStream<TcpStream>>;

pub trait CentralizedExchangeHandler {
    /// Create a new Handler.
    fn new(base_token: Token, quote_token: Token) -> Self;
    /// Get the websocket URL to connect to.
    fn websocket_url(&self) -> String;
    /// Certain exchanges report the most recent price immediately after subscribing to the
    /// websocket. If the exchange requires an initial request to get caught up with exchange
    /// state, we query that here.
    fn pre_stream_price_report(&mut self) -> Option<PriceReport>;
    /// Send any initial subscription messages to the websocket after it has been created.
    fn websocket_subscribe(&self, socket: &mut WebSocket) -> Result<(), ReporterError>;
    /// Handle an inbound message from the exchange by parsing it into a PriceReport and publishing
    /// the PriceReport into the ring buffer channel.
    fn handle_exchange_message(&mut self, message_json: Value) -> Option<PriceReport>;
}

#[derive(Clone, Debug)]
pub struct BinanceHandler {
    base_token: Token,
    quote_token: Token,
}
impl CentralizedExchangeHandler for BinanceHandler {
    fn new(base_token: Token, quote_token: Token) -> Self {
        Self {
            base_token,
            quote_token,
        }
    }

    fn websocket_url(&self) -> String {
        let base_ticker = self
            .base_token
            .get_exchange_ticker(Exchange::Binance)
            .unwrap();
        let quote_ticker = self
            .quote_token
            .get_exchange_ticker(Exchange::Binance)
            .unwrap();
        format!(
            "wss://stream.binance.com:443/ws/{}{}@bookTicker",
            base_ticker.to_lowercase(),
            quote_ticker.to_lowercase()
        )
    }

    fn pre_stream_price_report(&mut self) -> Option<PriceReport> {
        // TODO: This is duplicate code, condense it.
        let base_ticker = self
            .base_token
            .get_exchange_ticker(Exchange::Binance)
            .unwrap();
        let quote_ticker = self
            .quote_token
            .get_exchange_ticker(Exchange::Binance)
            .unwrap();
        let request_url = format!(
            "https://api.binance.com/api/v3/ticker/bookTicker?symbol={}{}",
            base_ticker, quote_ticker
        );
        let message_json: Value =
            block_on(block_on(reqwest::get(request_url)).unwrap().json()).unwrap();
        let best_bid: f64 = match message_json["bidPrice"].as_str() {
            None => {
                return None;
            }
            Some(best_bid_str) => best_bid_str.parse().unwrap(),
        };
        let best_offer: f64 = match message_json["askPrice"].as_str() {
            None => {
                return None;
            }
            Some(best_offer_str) => best_offer_str.parse().unwrap(),
        };
        Some(PriceReport {
            exchange: Some(Exchange::Binance),
            midpoint_price: (best_bid + best_offer) / 2.0,
            reported_timestamp: None,
            local_timestamp: get_current_time(),
        })
    }

    fn websocket_subscribe(&self, _socket: &mut WebSocket) -> Result<(), ReporterError> {
        // Binance begins streaming prices immediately; no initial subscribe message needed.
        Ok(())
    }

    fn handle_exchange_message(&mut self, message_json: Value) -> Option<PriceReport> {
        let best_bid: f64 = match message_json["b"].as_str() {
            None => {
                return None;
            }
            Some(best_bid_str) => best_bid_str.parse().unwrap(),
        };
        let best_offer: f64 = match message_json["a"].as_str() {
            None => {
                return None;
            }
            Some(best_offer_str) => best_offer_str.parse().unwrap(),
        };
        Some(PriceReport {
            exchange: Some(Exchange::Binance),
            midpoint_price: (best_bid + best_offer) / 2.0,
            reported_timestamp: None,
            local_timestamp: Default::default(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct CoinbaseHandler {
    base_token: Token,
    quote_token: Token,
    // Note: The reason we use String's for price_level is because using f32 as a key produces
    // collision issues.
    order_book_bids: HashMap<String, f32>,
    order_book_offers: HashMap<String, f32>,
}
impl CentralizedExchangeHandler for CoinbaseHandler {
    fn new(base_token: Token, quote_token: Token) -> Self {
        Self {
            base_token,
            quote_token,
            order_book_bids: HashMap::new(),
            order_book_offers: HashMap::new(),
        }
    }

    fn websocket_url(&self) -> String {
        String::from("wss://advanced-trade-ws.coinbase.com")
    }

    fn pre_stream_price_report(&mut self) -> Option<PriceReport> {
        None
    }

    fn websocket_subscribe(&self, socket: &mut WebSocket) -> Result<(), ReporterError> {
        let base_ticker = self
            .base_token
            .get_exchange_ticker(Exchange::Coinbase)
            .unwrap();
        let quote_ticker = self
            .quote_token
            .get_exchange_ticker(Exchange::Coinbase)
            .unwrap();
        let product_ids = format!("{}-{}", base_ticker, quote_ticker);
        let channel = "level2";
        let timestamp = (get_current_time() / 1000).to_string();
        let signature_bytes = HMAC::mac(
            format!("{}{}{}", timestamp, channel, product_ids),
            env::var("COINBASE_API_SECRET").unwrap(),
        );
        let signature = hex::encode(signature_bytes);
        let subscribe_str = json!({
            "type": "subscribe",
            "product_ids": [ product_ids ],
            "channel": channel,
            "api_key": env::var("COINBASE_API_KEY").unwrap(),
            "timestamp": timestamp,
            "signature": signature,
        })
        .to_string();
        socket
            .write_message(Message::Text(subscribe_str))
            .or(Err(ReporterError::ConnectionHangup))?;
        Ok(())
    }

    fn handle_exchange_message(&mut self, message_json: Value) -> Option<PriceReport> {
        // Extract the list of events and update the order book.
        let coinbase_events = match &message_json["events"] {
            Value::Array(coinbase_events) => match &coinbase_events[0]["updates"] {
                Value::Array(coinbase_events) => coinbase_events,
                _ => {
                    return None;
                }
            },
            _ => {
                return None;
            }
        };
        for coinbase_event in coinbase_events {
            let (price_level, new_quantity, side) = match (
                &coinbase_event["price_level"],
                &coinbase_event["new_quantity"],
                &coinbase_event["side"],
            ) {
                (Value::String(price_level), Value::String(new_quantity), Value::String(side)) => (
                    price_level.to_string(),
                    new_quantity.parse::<f32>().unwrap(),
                    side,
                ),
                _ => {
                    return None;
                }
            };
            match &side[..] {
                "bid" => {
                    self.order_book_bids
                        .insert(price_level.clone(), new_quantity);
                    if new_quantity == 0.0 {
                        self.order_book_bids.remove(&price_level);
                    }
                }
                "offer" => {
                    self.order_book_offers
                        .insert(price_level.clone(), new_quantity);
                    if new_quantity == 0.0 {
                        self.order_book_offers.remove(&price_level);
                    }
                }
                _ => {
                    return None;
                }
            }
        }

        // Given the new order book, compute the best bid and offer.
        let mut best_bid: f64 = 0.0;
        let mut best_offer: f64 = f64::INFINITY;
        for price_level in self.order_book_bids.keys() {
            best_bid = f64::max(best_bid, price_level.parse::<f64>().unwrap());
        }
        for price_level in self.order_book_offers.keys() {
            best_offer = f64::min(best_offer, price_level.parse::<f64>().unwrap());
        }

        let reported_timestamp =
            match DateTime::parse_from_rfc3339(message_json["timestamp"].as_str().unwrap()) {
                Ok(reported_timestamp) => reported_timestamp,
                Err(_) => {
                    return None;
                }
            }
            .timestamp_millis();
        Some(PriceReport {
            exchange: Some(Exchange::Coinbase),
            midpoint_price: (best_bid + best_offer) / 2.0,
            reported_timestamp: Some(reported_timestamp.try_into().unwrap()),
            local_timestamp: Default::default(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct KrakenHandler {
    base_token: Token,
    quote_token: Token,
}
impl CentralizedExchangeHandler for KrakenHandler {
    fn new(base_token: Token, quote_token: Token) -> Self {
        Self {
            base_token,
            quote_token,
        }
    }

    fn websocket_url(&self) -> String {
        String::from("wss://ws.kraken.com")
    }

    fn pre_stream_price_report(&mut self) -> Option<PriceReport> {
        None
    }

    fn websocket_subscribe(&self, socket: &mut WebSocket) -> Result<(), ReporterError> {
        let base_ticker = self
            .base_token
            .get_exchange_ticker(Exchange::Kraken)
            .unwrap();
        let quote_ticker = self
            .quote_token
            .get_exchange_ticker(Exchange::Kraken)
            .unwrap();
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
            .write_message(Message::Text(subscribe_str))
            .or(Err(ReporterError::ConnectionHangup))?;
        Ok(())
    }

    fn handle_exchange_message(&mut self, message_json: Value) -> Option<PriceReport> {
        let best_bid = match &message_json[1][0] {
            Value::String(best_bid) => best_bid.parse::<f64>().unwrap(),
            _ => {
                return None;
            }
        };
        let best_offer = match &message_json[1][1] {
            Value::String(best_offer) => best_offer.parse::<f64>().unwrap(),
            _ => {
                return None;
            }
        };
        let reported_timestamp_seconds = match &message_json[1][2] {
            Value::String(reported_timestamp) => reported_timestamp.parse::<f32>().unwrap(),
            _ => {
                return None;
            }
        };
        Some(PriceReport {
            exchange: Some(Exchange::Kraken),
            midpoint_price: (best_bid + best_offer) / 2.0,
            reported_timestamp: Some((reported_timestamp_seconds * 1000.0) as u128),
            local_timestamp: Default::default(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct OkxHandler {
    base_token: Token,
    quote_token: Token,
}
impl CentralizedExchangeHandler for OkxHandler {
    fn new(base_token: Token, quote_token: Token) -> Self {
        Self {
            base_token,
            quote_token,
        }
    }

    fn websocket_url(&self) -> String {
        String::from("wss://ws.okx.com:8443/ws/v5/public")
    }

    fn pre_stream_price_report(&mut self) -> Option<PriceReport> {
        None
    }

    fn websocket_subscribe(&self, socket: &mut WebSocket) -> Result<(), ReporterError> {
        let base_ticker = self.base_token.get_exchange_ticker(Exchange::Okx).unwrap();
        let quote_ticker = self.quote_token.get_exchange_ticker(Exchange::Okx).unwrap();
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
            .write_message(Message::Text(subscribe_str))
            .or(Err(ReporterError::ConnectionHangup))?;
        Ok(())
    }

    fn handle_exchange_message(&mut self, message_json: Value) -> Option<PriceReport> {
        let best_bid = match &message_json["data"][0]["bids"][0][0] {
            Value::String(best_bid) => best_bid.parse::<f64>().unwrap(),
            _ => {
                return None;
            }
        };
        let best_offer = match &message_json["data"][0]["asks"][0][0] {
            Value::String(best_offer) => best_offer.parse::<f64>().unwrap(),
            _ => {
                return None;
            }
        };
        let reported_timestamp_seconds = match &message_json["data"][0]["ts"] {
            Value::String(reported_timestamp) => reported_timestamp.parse::<f32>().unwrap(),
            _ => {
                return None;
            }
        };
        Some(PriceReport {
            exchange: Some(Exchange::Okx),
            midpoint_price: (best_bid + best_offer) / 2.0,
            reported_timestamp: Some((reported_timestamp_seconds * 1000.0) as u128),
            local_timestamp: Default::default(),
        })
    }
}
