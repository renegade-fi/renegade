//! Defines abstract connection interfaces that can be streamed from

use async_trait::async_trait;
use futures::stream::StreamExt;
use futures_util::{
    stream::{SplitSink, SplitStream},
    Stream,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fmt::{self, Display},
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use tracing::log;
use url::Url;

use crate::price_reporter::{reporter::Price, worker::PriceReporterManagerConfig};

use super::super::{errors::ExchangeConnectionError, reporter::PriceReport, tokens::Token};

// -------------
// | Constants |
// -------------

/// The message passed when Okx observes a protocol violation
const PROTOCOL_VIOLATION_MSG: &str = "Protocol violation";
/// The message Okx passes in response to a keepalive ping
const PONG_MESSAGE: &str = "pong";
/// The message passed when a ws proxy resets
const CLOUDFLARE_RESET_MESSAGE: &str = "CloudFlare WebSocket proxy restarting";

// -----------
// | Helpers |
// -----------

/// Build a websocket connection to the given endpoint
pub(super) async fn ws_connect(
    url: Url,
) -> Result<
    (
        SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
        SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    ),
    ExchangeConnectionError,
> {
    let ws_conn = match connect_async(url.clone()).await {
        Ok((conn, _resp)) => conn,
        Err(e) => {
            log::error!("Cannot connect to the remote URL: {}", url);
            return Err(ExchangeConnectionError::HandshakeFailure(e.to_string()));
        }
    };

    let (ws_sink, ws_stream) = ws_conn.split();
    Ok((ws_sink, ws_stream))
}

/// Helper to parse a value from a JSON response
pub(super) fn parse_json_field<T: FromStr>(
    field_name: &str,
    response: &Value,
) -> Result<T, ExchangeConnectionError> {
    match response[field_name].as_str() {
        None => Err(ExchangeConnectionError::InvalidMessage(
            response.to_string(),
        )),
        Some(field_value) => field_value
            .parse()
            .map_err(|_| ExchangeConnectionError::InvalidMessage(response.to_string())),
    }
}

/// Helper to parse a value from a JSON response by index
pub(super) fn parse_json_field_array<T: FromStr>(
    field_index: usize,
    response: &Value,
) -> Result<T, ExchangeConnectionError> {
    match response[field_index].as_str() {
        None => Err(ExchangeConnectionError::InvalidMessage(
            response.to_string(),
        )),
        Some(field_value) => field_value
            .parse()
            .map_err(|_| ExchangeConnectionError::InvalidMessage(response.to_string())),
    }
}

/// Parse an json structure from a websocket message
pub fn parse_json_from_message(message: Message) -> Result<Option<Value>, ExchangeConnectionError> {
    if let Message::Text(message_str) = message {
        // Okx sends some undocumented messages: Empty strings and "Protocol violation" messages
        if message_str == PROTOCOL_VIOLATION_MSG || message_str.is_empty() {
            return Ok(None);
        }

        // Okx sends "pong" messages from our "ping" messages
        if message_str == PONG_MESSAGE {
            return Ok(None);
        }

        // Okx and Kraken send "CloudFlare WebSocket proxy restarting" messages
        if message_str == CLOUDFLARE_RESET_MESSAGE {
            return Ok(None);
        }

        // Parse into a json blob
        serde_json::from_str(&message_str).map_err(|err| {
            ExchangeConnectionError::InvalidMessage(format!("{} for message: {}", err, message_str))
        })
    } else {
        Ok(None)
    }
}

/// Helper function to get the current UNIX epoch time in milliseconds
pub fn get_current_time() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

// --------------------------
// | Connection Abstraction |
// --------------------------

/// The state of an ExchangeConnection. Note that the ExchangeConnection itself simply streams news
/// PriceReports, and the task of determining if the PriceReports have yet to arrive is the job of
/// the PriceReporter
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

/// A trait representing a connection to an exchange
#[async_trait]
pub trait ExchangeConnection: Stream<Item = Price> + Unpin + Send {
    /// Create a new connection to the exchange on a given asset pair
    async fn connect(
        base_token: Token,
        quote_token: Token,
        config: &PriceReporterManagerConfig,
    ) -> Result<Self, ExchangeConnectionError>
    where
        Self: Sized;
    /// Send a keepalive signal on the connection if necessary
    async fn send_keepalive(&mut self) -> Result<(), ExchangeConnectionError> {
        Ok(())
    }
}
