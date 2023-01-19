use futures::{stream::StreamExt, SinkExt};
use ring_channel::{ring_channel, RingReceiver, RingSender};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Display},
    num::NonZeroUsize,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    runtime::Handle,
    time::{sleep, Duration},
};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use url::Url;

use super::super::{
    errors::ExchangeConnectionError,
    exchanges::handlers_centralized::{
        BinanceHandler, CentralizedExchangeHandler, CoinbaseHandler, KrakenHandler, OkxHandler,
    },
    exchanges::handlers_decentralized::UniswapV3Handler,
    reporter::PriceReport,
    tokens::Token,
};

/// Each sub-thread spawned by an ExchangeConnection must return a vector WorkerHandles: These are
/// used for error propagation back to the PriceReporter.
pub type WorkerHandles = Vec<tokio::task::JoinHandle<Result<(), ExchangeConnectionError>>>;

/// Helper function to get the current UNIX epoch time in milliseconds.
pub fn get_current_time() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

/// The type of exchange. Note that `Exchange` is the abstract enum for all exchanges that are
/// supported, whereas the `ExchangeConnection` is the actual instantiation of a websocket price
/// stream from an `Exchange`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum Exchange {
    /// Binance.
    Binance,
    /// Coinbase.
    Coinbase,
    /// Kraken.
    Kraken,
    /// Okx.
    Okx,
    /// UniswapV3.
    UniswapV3,
}
impl Display for Exchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fmt_str = match self {
            Exchange::Binance => String::from("binance"),
            Exchange::Coinbase => String::from("coinbase"),
            Exchange::Kraken => String::from("kraken"),
            Exchange::Okx => String::from("okx"),
            Exchange::UniswapV3 => String::from("uniswapv3"),
        };
        write!(f, "{}", fmt_str)
    }
}

/// Every Exchange.
pub static ALL_EXCHANGES: &[Exchange] = &[
    Exchange::Binance,
    Exchange::Coinbase,
    Exchange::Kraken,
    Exchange::Okx,
    Exchange::UniswapV3,
];

/// The state of an ExchangeConnection. Note that the ExchangeConnection itself simply streams news
/// PriceReports, and the task of determining if the PriceReports have yet to arrive is the job of
/// the PriceReporter.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ExchangeConnectionState {
    /// The ExchangeConnection is reporting as normal.
    Nominal(PriceReport),
    /// No data has yet to be reported from the ExchangeConnection.
    NoDataReported,
    /// This Exchange is unsupported for the given Token pair
    Unsupported,
}
impl Display for ExchangeConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fmt_str = match self {
            ExchangeConnectionState::Nominal(price_report) => {
                format!("{:.4}", price_report.midpoint_price)
            }
            ExchangeConnectionState::NoDataReported => String::from("NoDataReported"),
            ExchangeConnectionState::Unsupported => String::from("Unsupported"),
        };
        write!(f, "{}", fmt_str)
    }
}

/// A connection to an `Exchange`. Note that creating an `ExchangeConnection` via
/// `ExchangeConnection::new(exchange: Exchange)` only returns a ring buffer channel receiver; the
/// ExchangeConnection is never directly accessed, and all data is reported only via this receiver.
#[derive(Clone, Debug)]
pub struct ExchangeConnection {
    /// The CentralizedExchangeHandler for Binance.
    binance_handler: Option<BinanceHandler>,
    /// The CentralizedExchangeHandler for Coinbase.
    coinbase_handler: Option<CoinbaseHandler>,
    /// The CentralizedExchangeHandler for Kraken.
    kraken_handler: Option<KrakenHandler>,
    /// The CentralizedExchangeHandler for Okx.
    okx_handler: Option<OkxHandler>,
}
impl ExchangeConnection {
    /// Create a new ExchangeConnection, returning the RingReceiver of PriceReports. Note that the
    /// role of the ExchangeConnection is to simply stream PriceReports as they come, and does not
    /// do any staleness testing or cross-Exchange deviation checks.
    pub async fn create_receiver(
        base_token: Token,
        quote_token: Token,
        exchange: Exchange,
        tokio_handle: Handle,
    ) -> Result<(RingReceiver<PriceReport>, WorkerHandles), ExchangeConnectionError> {
        // Create the vector of JoinHandles for all spawned threads.
        let mut worker_handles: WorkerHandles = vec![];

        // Create the ring buffer.
        let (mut price_report_sender, price_report_receiver) =
            ring_channel::<PriceReport>(NonZeroUsize::new(1).unwrap());

        // UniswapV3 logic is slightly different, as we use the web3 API wrapper for convenience,
        // rather than interacting directly over websockets.
        if exchange == Exchange::UniswapV3 {
            let worker_handles = UniswapV3Handler::start_price_stream(
                base_token,
                quote_token,
                price_report_sender,
                tokio_handle,
            )
            .await?;
            return Ok((price_report_receiver, worker_handles));
        }

        // Get initial ExchangeHandler state and include in a new ExchangeConnection.
        let mut exchange_connection = match exchange {
            Exchange::Binance => ExchangeConnection {
                binance_handler: Some(BinanceHandler::new(base_token, quote_token)),
                coinbase_handler: None,
                kraken_handler: None,
                okx_handler: None,
            },
            Exchange::Coinbase => ExchangeConnection {
                binance_handler: None,
                coinbase_handler: Some(CoinbaseHandler::new(base_token, quote_token)),
                kraken_handler: None,
                okx_handler: None,
            },
            Exchange::Kraken => ExchangeConnection {
                binance_handler: None,
                coinbase_handler: None,
                kraken_handler: Some(KrakenHandler::new(base_token, quote_token)),
                okx_handler: None,
            },
            Exchange::Okx => ExchangeConnection {
                binance_handler: None,
                coinbase_handler: None,
                kraken_handler: None,
                okx_handler: Some(OkxHandler::new(base_token, quote_token)),
            },
            _ => unreachable!(),
        };

        // Retrieve the optional pre-stream PriceReport.
        let pre_stream_price_report = match exchange {
            Exchange::Binance => exchange_connection
                .binance_handler
                .as_mut()
                .unwrap()
                .pre_stream_price_report(),
            Exchange::Coinbase => exchange_connection
                .coinbase_handler
                .as_mut()
                .unwrap()
                .pre_stream_price_report(),
            Exchange::Kraken => exchange_connection
                .kraken_handler
                .as_mut()
                .unwrap()
                .pre_stream_price_report(),
            Exchange::Okx => exchange_connection
                .okx_handler
                .as_mut()
                .unwrap()
                .pre_stream_price_report(),
            _ => unreachable!(),
        }
        .await;
        if let Some(pre_stream_price_report) = pre_stream_price_report? {
            let mut price_report_sender_clone = price_report_sender.clone();
            tokio_handle.spawn(async move {
                // TODO: Sleeping is a somewhat hacky way of ensuring that the
                // pre_stream_price_report is received.
                sleep(Duration::from_secs(5)).await;
                price_report_sender_clone
                    .send(pre_stream_price_report)
                    .map_err(|err| ExchangeConnectionError::ConnectionHangup(err.to_string()))?;
                Ok::<(), ExchangeConnectionError>(())
            });
        }

        // Retrieve the websocket URL and connect to it.
        let wss_url = match exchange {
            Exchange::Binance => exchange_connection
                .binance_handler
                .as_ref()
                .unwrap()
                .websocket_url(),
            Exchange::Coinbase => exchange_connection
                .coinbase_handler
                .as_ref()
                .unwrap()
                .websocket_url(),
            Exchange::Kraken => exchange_connection
                .kraken_handler
                .as_ref()
                .unwrap()
                .websocket_url(),
            Exchange::Okx => exchange_connection
                .okx_handler
                .as_ref()
                .unwrap()
                .websocket_url(),
            _ => unreachable!(),
        };
        let url = Url::parse(&wss_url).unwrap();
        let (mut socket, _response) = {
            let connection = connect_async(url).await;
            if let Ok(connection) = connection {
                connection
            } else {
                if exchange == Exchange::Binance {
                    println!(
                        "You are likely attempting to connect from an IP address \
                        blacklisted by Binance (e.g., anything US-based)"
                    );
                }
                println!("Cannot connect to the remote URL: {}", wss_url);
                return Err(ExchangeConnectionError::HandshakeFailure(
                    connection.unwrap_err().to_string(),
                ));
            }
        };

        // Send initial subscription message(s).
        match exchange {
            Exchange::Binance => exchange_connection
                .binance_handler
                .as_ref()
                .unwrap()
                .websocket_subscribe(&mut socket),
            Exchange::Coinbase => exchange_connection
                .coinbase_handler
                .as_ref()
                .unwrap()
                .websocket_subscribe(&mut socket),
            Exchange::Kraken => exchange_connection
                .kraken_handler
                .as_ref()
                .unwrap()
                .websocket_subscribe(&mut socket),
            Exchange::Okx => exchange_connection
                .okx_handler
                .as_ref()
                .unwrap()
                .websocket_subscribe(&mut socket),
            _ => unreachable!(),
        }
        .await?;

        // Start listening for inbound messages.
        let (mut socket_sink, mut socket_stream) = socket.split();
        let worker_handle = tokio_handle.spawn(async move {
            loop {
                let message =
                    socket_stream.next().await.unwrap().map_err(|err| {
                        ExchangeConnectionError::ConnectionHangup(err.to_string())
                    })?;
                exchange_connection.handle_exchange_message(&mut price_report_sender, message)?;
            }
        });
        worker_handles.push(worker_handle);

        // Periodically send a ping to prevent websocket hangup
        let worker_handle = tokio_handle.spawn(async move {
            loop {
                sleep(Duration::from_secs(30)).await;
                socket_sink.send(Message::Ping(vec![])).await.unwrap();
            }
        });
        worker_handles.push(worker_handle);

        Ok((price_report_receiver, worker_handles))
    }

    /// Simple wrapper around each individual ExchangeConnection handle_exchange_message.
    fn handle_exchange_message(
        &mut self,
        price_report_sender: &mut RingSender<PriceReport>,
        message: Message,
    ) -> Result<(), ExchangeConnectionError> {
        let message_str = message.into_text().unwrap();
        // Sometimes OKX sends an undocumented "Protocol violation" message, likely from rate
        // limiting. Also, sometimes we receive empty messages. We ignore these.
        if message_str == "Protocol violation" || message_str.is_empty() {
            return Ok(());
        }
        let message_json = serde_json::from_str(&message_str)
            .map_err(|err| ExchangeConnectionError::InvalidMessage(err.to_string()))?;

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
        }?;

        if let Some(mut price_report) = price_report {
            price_report.local_timestamp = get_current_time();
            price_report_sender.send(price_report).unwrap();
        }

        Ok(())
    }
}
