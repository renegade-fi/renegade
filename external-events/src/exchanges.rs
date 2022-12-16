use chrono::DateTime;
use hmac_sha256::HMAC;
use ring_channel::{ring_channel, RingReceiver, RingSender};
use serde_json::{self, json, Value};
use std::num::NonZeroUsize;
use std::{
    env,
    net::TcpStream,
    thread,
    time::{SystemTime, UNIX_EPOCH},
};
use tungstenite::{connect, stream::MaybeTlsStream, Message, WebSocket as WebSocketGeneric};
use url::Url;

use crate::{errors::ReporterError, reporters::PriceReport};

fn get_current_time() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

type WebSocket = WebSocketGeneric<MaybeTlsStream<TcpStream>>;

/// The type of exchange. Note that `Exchange` is the abstract enum for all exchanges that are
/// supported, whereas the `ExchangeConnection` is the actual instantiation of a websocket price
/// stream from an `Exchange`.
#[derive(Clone, Debug, Copy)]
pub enum Exchange {
    Binance,
    Coinbase,
    // Kraken,
    // Okx,
    // KuCoin,
    // Huobi,
    // Uniswap,
}

/// A connection to an `Exchange`. Note that creating an `ExchangeConnection` via
/// `ExchangeConnection::new(exchange: Exchange)` only returns a ring buffer channel receiver; the
/// ExchangeConnection is never directly accessed, and all data is reported only via this receiver.
pub struct ExchangeConnection {
    binance_handler: Option<BinanceHandler>,
    coinbase_handler: Option<CoinbaseHandler>,
}
impl ExchangeConnection {
    pub fn new(exchange: Exchange) -> Result<RingReceiver<PriceReport>, ReporterError> {
        // Create the ring buffer.
        let (mut price_report_sender, price_report_receiver) =
            ring_channel::<PriceReport>(NonZeroUsize::new(1).unwrap());

        // Retrieve the websocket URL and connect to it.
        let wss_url = match exchange {
            Exchange::Binance => BinanceHandler::WSS_URL,
            Exchange::Coinbase => CoinbaseHandler::WSS_URL,
        };
        let url = Url::parse(&wss_url).unwrap();
        let (mut socket, _response) = connect(url).or(Err(ReporterError::ConnectionFailure))?;

        // Send initial subscription message(s).
        match exchange {
            Exchange::Binance => BinanceHandler::websocket_subscribe(&mut socket)?,
            Exchange::Coinbase => CoinbaseHandler::websocket_subscribe(&mut socket)?,
        }

        // Get initial ExchangeHandler state and include in a new ExchangeConnection.
        let exchange_connection = match exchange {
            Exchange::Binance => ExchangeConnection {
                binance_handler: Some(BinanceHandler::new()),
                coinbase_handler: None,
            },
            Exchange::Coinbase => ExchangeConnection {
                binance_handler: None,
                coinbase_handler: Some(CoinbaseHandler::new()),
            },
        };

        // Start listening for inbound messages.
        thread::spawn(move || loop {
            let message = socket.read_message().unwrap();
            exchange_connection.handle_exchange_message(&mut price_report_sender, message);
        });

        Ok(price_report_receiver)
    }

    fn handle_exchange_message(
        &self,
        price_report_sender: &mut RingSender<PriceReport>,
        message: Message,
    ) {
        let message_str = message.into_text().unwrap();
        let message_json = serde_json::from_str(&message_str).unwrap();

        let price_report = {
            if let Some(binance_handler) = self.binance_handler {
                binance_handler.handle_exchange_message(message_json)
            } else if let Some(coinbase_handler) = self.coinbase_handler {
                coinbase_handler.handle_exchange_message(message_json)
            } else {
                panic!("Unreachable.");
            }
        };

        if let Some(price_report) = price_report {
            price_report_sender.send(price_report).unwrap();
        }
    }
}

trait ExchangeHandlerApi {
    const WSS_URL: &'static str;
    fn websocket_subscribe(socket: &mut WebSocket) -> Result<(), ReporterError>;
    fn new() -> Self;
    /// Handle an inbound message from the exchange by parsing it into a PriceReport and publishing
    /// the PriceReport into the ring buffer channel.
    fn handle_exchange_message(&self, message_json: Value) -> Option<PriceReport>;
}

#[derive(Clone, Copy, Debug)]
struct BinanceHandler {}
impl ExchangeHandlerApi for BinanceHandler {
    const WSS_URL: &'static str = "wss://stream.binance.com:443/ws/ethbusd@bookTicker";

    fn websocket_subscribe(_socket: &mut WebSocket) -> Result<(), ReporterError> {
        // Binance begins streaming prices immediately; no initial subscribe message needed.
        Ok(())
    }

    fn new() -> Self {
        // BinanceHandler has no internal state.
        Self {}
    }

    fn handle_exchange_message(&self, message_json: Value) -> Option<PriceReport> {
        let best_bid: f32 = match message_json["b"].as_str() {
            None => {
                return None;
            }
            Some(best_bid_str) => best_bid_str.parse().unwrap(),
        };
        let best_offer: f32 = match message_json["a"].as_str() {
            None => {
                return None;
            }
            Some(best_offer_str) => best_offer_str.parse().unwrap(),
        };
        Some(PriceReport {
            midpoint_price: (best_bid + best_offer) / 2.0,
            reported_timestamp: None,
            local_timestamp: get_current_time(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct CoinbaseHandler {}
impl ExchangeHandlerApi for CoinbaseHandler {
    const WSS_URL: &'static str = "wss://advanced-trade-ws.coinbase.com";

    fn websocket_subscribe(socket: &mut WebSocket) -> Result<(), ReporterError> {
        let product_ids = "ETH-USD";
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
            .or(Err(ReporterError::ConnectionFailure))?;
        Ok(())
    }

    fn new() -> Self {
        Self {}
    }

    fn handle_exchange_message(&self, message_json: Value) -> Option<PriceReport> {
        // Extract the list of events and compute the best bid and offer.
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
        let mut best_bid: f32 = 0.0;
        let mut best_offer: f32 = f32::INFINITY;
        for coinbase_event in coinbase_events {
            let (price_level, side) =
                match (&coinbase_event["price_level"], &coinbase_event["side"]) {
                    (Value::String(price_level), Value::String(side)) => {
                        (price_level.parse::<f32>().unwrap(), side)
                    }
                    _ => {
                        return None;
                    }
                };
            match &side[..] {
                "offer" => {
                    best_offer = f32::min(best_offer, price_level);
                }
                "bid" => {
                    best_bid = f32::max(best_bid, price_level);
                }
                _ => {
                    return None;
                }
            }
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
            midpoint_price: (best_bid + best_offer) / 2.0,
            reported_timestamp: Some(reported_timestamp.try_into().unwrap()),
            local_timestamp: get_current_time(),
        })
    }
}
