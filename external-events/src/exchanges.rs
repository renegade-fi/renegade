use chrono::DateTime;
use hmac_sha256::HMAC;
use ring_channel::RingSender;
use serde_json::{self, json, Value};
use std::{
    env, thread,
    time::{SystemTime, UNIX_EPOCH},
};
use tungstenite::{connect, Message};
use url::Url;

use crate::{errors::ReporterError, reporters::PriceReport};

#[derive(Clone, Debug, Copy)]
pub enum Exchange {
    Binance,
    Coinbase,
    // Kraken,
    // Okx,
    // Uniswap,
}

impl Exchange {
    pub fn setup_exchange_connection(
        &self,
        price_report_sender: RingSender<PriceReport>,
    ) -> Result<(), ReporterError> {
        match self {
            Self::Binance => Binance::setup_exchange_connection(price_report_sender),
            Self::Coinbase => Coinbase::setup_exchange_connection(price_report_sender),
        }
    }
}

fn get_current_time() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

trait ExchangeConnection {
    fn setup_exchange_connection(
        price_report_sender: RingSender<PriceReport>,
    ) -> Result<(), ReporterError>;
    /// Handle an inbound message from the exchange by parsing it into a PriceReport and publishing
    /// the PriceReport into the ring buffer channel.
    fn handle_exchange_message(price_report_sender: &mut RingSender<PriceReport>, msg: &str);
}

struct Binance {}
impl ExchangeConnection for Binance {
    fn setup_exchange_connection(
        mut price_report_sender: RingSender<PriceReport>,
    ) -> Result<(), ReporterError> {
        let url = Url::parse("wss://stream.binance.com:443/ws/ethbusd@bookTicker").unwrap();
        let (mut socket, _response) = connect(url).or(Err(ReporterError::ConnectionFailure))?;
        thread::spawn(move || loop {
            let message = socket.read_message().unwrap();
            Self::handle_exchange_message(&mut price_report_sender, &message.into_text().unwrap());
        });
        Ok(())
    }

    fn handle_exchange_message(price_report_sender: &mut RingSender<PriceReport>, msg: &str) {
        let msg_json: Value = serde_json::from_str(msg).unwrap();
        let best_bid: f32 = match msg_json["b"].as_str() {
            None => return,
            Some(best_bid_str) => best_bid_str.parse().unwrap(),
        };
        let best_offer: f32 = match msg_json["a"].as_str() {
            None => return,
            Some(best_offer_str) => best_offer_str.parse().unwrap(),
        };
        let price_report = PriceReport {
            midpoint_price: (best_bid + best_offer) / 2.0,
            reported_timestamp: None,
            local_timestamp: get_current_time(),
        };
        price_report_sender.send(price_report).unwrap();
    }
}

struct Coinbase {}
impl ExchangeConnection for Coinbase {
    fn setup_exchange_connection(
        mut price_report_sender: RingSender<PriceReport>,
    ) -> Result<(), ReporterError> {
        let url = Url::parse("wss://advanced-trade-ws.coinbase.com").unwrap();
        let (mut socket, _response) = connect(url).or(Err(ReporterError::ConnectionFailure))?;

        // Send a subscribe message.
        let product_ids = "ETH-USD";
        let channel = "level2";
        let timestamp = (get_current_time() / 1000).to_string();
        let signature_bytes = HMAC::mac(
            format!("{}{}{}", timestamp, channel, product_ids),
            env::var("COINBASE_API_SECRET").unwrap(),
        );
        let mut signature = hex::encode(signature_bytes);
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

        // Start listening for inbound messages.
        thread::spawn(move || loop {
            let message = socket.read_message().unwrap();
            Self::handle_exchange_message(&mut price_report_sender, &message.into_text().unwrap());
        });
        Ok(())
    }

    fn handle_exchange_message(price_report_sender: &mut RingSender<PriceReport>, msg: &str) {
        let msg_json: Value = serde_json::from_str(msg).unwrap();

        // Extract the list of events and compute the best bid and offer.
        let coinbase_events = match &msg_json["events"] {
            Value::Array(coinbase_events) => match &coinbase_events[0]["updates"] {
                Value::Array(coinbase_events) => coinbase_events,
                _ => {
                    return;
                }
            },
            _ => {
                return;
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
                        return;
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
                    println!("BAD");
                    return;
                }
            }
        }

        let reported_timestamp =
            match DateTime::parse_from_rfc3339(msg_json["timestamp"].as_str().unwrap()) {
                Ok(reported_timestamp) => reported_timestamp,
                Err(_) => {
                    return;
                }
            }
            .timestamp_millis();
        let local_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let price_report = PriceReport {
            midpoint_price: (best_bid + best_offer) / 2.0,
            reported_timestamp: Some(reported_timestamp.try_into().unwrap()),
            local_timestamp,
        };
        price_report_sender.send(price_report).unwrap();
    }
}
