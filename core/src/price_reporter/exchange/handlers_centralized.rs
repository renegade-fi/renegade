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
