use ring_channel::RingSender;
use serde_json::{self, Value};
use std::{
    thread,
    time::{SystemTime, UNIX_EPOCH},
};
use tungstenite::connect;
use url::Url;

use crate::{errors::ReporterError, reporters::PriceReport};

#[derive(Clone, Debug, Copy)]
pub enum Exchange {
    Binance,
    // Coinbase,
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
            // Self::Coinbase => Coinbase::setup_exchange_connection(price_report_sender),
        }
    }
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
        let local_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let price_report = PriceReport {
            midpoint_price: (best_bid + best_offer) / 2.0,
            reported_timestamp: None,
            local_timestamp,
        };
        price_report_sender.send(price_report).unwrap();
    }
}

