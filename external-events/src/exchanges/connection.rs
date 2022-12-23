use ring_channel::{ring_channel, RingReceiver, RingSender};
use std::{
    num::NonZeroUsize,
    thread,
    time::{SystemTime, UNIX_EPOCH},
};
use tungstenite::{connect, Message};
use url::Url;

use crate::{
    errors::ReporterError,
    exchanges::handlers_centralized::{
        BinanceHandler, CentralizedExchangeHandler, CoinbaseHandler, KrakenHandler, OkxHandler,
    },
    exchanges::handlers_decentralized::UniswapV3Handler,
    reporter::PriceReport,
    tokens::Token,
};

pub fn get_current_time() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

/// The type of exchange. Note that `Exchange` is the abstract enum for all exchanges that are
/// supported, whereas the `ExchangeConnection` is the actual instantiation of a websocket price
/// stream from an `Exchange`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Exchange {
    Median, /* Special exchange that aggregates the rest. */
    Binance,
    Coinbase,
    Kraken,
    Okx,
    UniswapV3,
}

/// A connection to an `Exchange`. Note that creating an `ExchangeConnection` via
/// `ExchangeConnection::new(exchange: Exchange)` only returns a ring buffer channel receiver; the
/// ExchangeConnection is never directly accessed, and all data is reported only via this receiver.
pub struct ExchangeConnection {
    binance_handler: Option<BinanceHandler>,
    coinbase_handler: Option<CoinbaseHandler>,
    kraken_handler: Option<KrakenHandler>,
    okx_handler: Option<OkxHandler>,
}
impl ExchangeConnection {
    pub fn create_receiver(
        base_token: Token,
        quote_token: Token,
        exchange: Exchange,
    ) -> Result<RingReceiver<PriceReport>, ReporterError> {
        // Create the ring buffer.
        let (mut price_report_sender, price_report_receiver) =
            ring_channel::<PriceReport>(NonZeroUsize::new(1).unwrap());

        // UniswapV3 logic is slightly different, as we use the web3 API wrapper for convenience,
        // rather than interacting directly over websockets.
        if exchange == Exchange::UniswapV3 {
            UniswapV3Handler::start_price_stream(base_token, quote_token, price_report_sender);
            return Ok(price_report_receiver);
        }

        // Retrieve the websocket URL and connect to it.
        let wss_url = match exchange {
            Exchange::Binance => BinanceHandler::WSS_URL,
            Exchange::Coinbase => CoinbaseHandler::WSS_URL,
            Exchange::Kraken => KrakenHandler::WSS_URL,
            Exchange::Okx => OkxHandler::WSS_URL,
            _ => unreachable!(),
        };
        let url = Url::parse(wss_url).unwrap();
        let (mut socket, _response) = connect(url).or(Err(ReporterError::ConnectionFailure))?;

        // Send initial subscription message(s).
        match exchange {
            Exchange::Binance => BinanceHandler::websocket_subscribe(&mut socket)?,
            Exchange::Coinbase => CoinbaseHandler::websocket_subscribe(&mut socket)?,
            Exchange::Kraken => KrakenHandler::websocket_subscribe(&mut socket)?,
            Exchange::Okx => OkxHandler::websocket_subscribe(&mut socket)?,
            _ => unreachable!(),
        }

        // Get initial ExchangeHandler state and include in a new ExchangeConnection.
        let mut exchange_connection = match exchange {
            Exchange::Binance => ExchangeConnection {
                binance_handler: Some(BinanceHandler::new()),
                coinbase_handler: None,
                kraken_handler: None,
                okx_handler: None,
            },
            Exchange::Coinbase => ExchangeConnection {
                binance_handler: None,
                coinbase_handler: Some(CoinbaseHandler::new()),
                kraken_handler: None,
                okx_handler: None,
            },
            Exchange::Kraken => ExchangeConnection {
                binance_handler: None,
                coinbase_handler: None,
                kraken_handler: Some(KrakenHandler::new()),
                okx_handler: None,
            },
            Exchange::Okx => ExchangeConnection {
                binance_handler: None,
                coinbase_handler: None,
                kraken_handler: None,
                okx_handler: Some(OkxHandler::new()),
            },
            _ => unreachable!(),
        };

        // Start listening for inbound messages.
        thread::spawn(move || loop {
            let message = socket.read_message().unwrap();
            exchange_connection.handle_exchange_message(&mut price_report_sender, message);
        });

        Ok(price_report_receiver)
    }

    fn handle_exchange_message(
        &mut self,
        price_report_sender: &mut RingSender<PriceReport>,
        message: Message,
    ) {
        let message_str = message.into_text().unwrap();
        let message_json = serde_json::from_str(&message_str).unwrap();

        let price_report = {
            if let Some(binance_handler) = &mut self.binance_handler {
                binance_handler.handle_exchange_message(message_json)
            } else if let Some(coinbase_handler) = &mut self.coinbase_handler {
                coinbase_handler.handle_exchange_message(message_json)
            } else if let Some(kraken_handler) = &mut self.kraken_handler {
                kraken_handler.handle_exchange_message(message_json)
            } else if let Some(okx_handler) = &mut self.okx_handler {
                okx_handler.handle_exchange_message(message_json)
            } else {
                unreachable!();
            }
        };

        if let Some(mut price_report) = price_report {
            price_report.local_timestamp = get_current_time();
            price_report_sender.send(price_report).unwrap();
        }
    }
}
