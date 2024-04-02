//! Defines the ExternalPriceReporterExecutor, a handler that is responsible for
//! executing individual PriceReporterJobs. This is used when the relayer opts
//! for streaming prices from an external price reporter service.

use std::{str::FromStr, time::Duration};

use common::{
    default_wrapper::DefaultOption,
    types::{
        exchange::{Exchange, PriceReporterState},
        token::Token,
        CancelChannel, Price,
    },
};
use external_api::websocket::WebsocketMessage;
use futures::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use job_types::price_reporter::{PriceReporterJob, PriceReporterReceiver};
use serde::{Deserialize, Serialize};
use tokio::{
    net::TcpStream,
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        oneshot::Sender as TokioSender,
    },
};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tracing::{error, info, info_span, warn, Instrument};
use tungstenite::Message;
use url::Url;
use util::{err_str, get_current_time_seconds};

use crate::{
    errors::{ExchangeConnectionError, PriceReporterError},
    exchange::connection::ws_connect,
    manager::CONN_RETRY_DELAY_MS,
    worker::PriceReporterConfig,
};

use super::PriceStreamStatesManager;

/// A type alias for the write end of the websocket connection
type WsWriteStream = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;

/// A type alias for the read end of the websocket connection
type WsReadStream = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

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

/// The actual executor that handles incoming jobs, to subscribe to
/// price streams, and peek at PriceReports.
#[derive(Clone)]
pub struct ExternalPriceReporterExecutor {
    /// The latest states of the all price streams
    price_stream_states: PriceStreamStatesManager,
    /// The manager config
    config: PriceReporterConfig,
    /// The channel along which jobs are passed to the price reporter
    job_receiver: DefaultOption<PriceReporterReceiver>,
    /// The channel on which the coordinator may cancel execution
    cancel_channel: DefaultOption<CancelChannel>,
}

impl ExternalPriceReporterExecutor {
    /// Creates the executor for the PriceReporter worker.
    pub(crate) fn new(
        job_receiver: PriceReporterReceiver,
        config: PriceReporterConfig,
        cancel_channel: CancelChannel,
    ) -> Self {
        Self {
            price_stream_states: PriceStreamStatesManager::new(config.clone()),
            config,
            job_receiver: DefaultOption::new(Some(job_receiver)),
            cancel_channel: DefaultOption::new(Some(cancel_channel)),
        }
    }

    /// The execution loop for the price reporter
    pub(crate) async fn execution_loop(mut self) -> Result<(), PriceReporterError> {
        let mut job_receiver = self.job_receiver.take().unwrap();
        let mut cancel_channel = self.cancel_channel.take().unwrap();

        // Spawn WS handler loop, which forwards reads/writes over channels
        let (msg_out_tx, mut msg_in_rx) = self.spawn_ws_handler_loop();

        loop {
            tokio::select! {
                // Process price update from external price reporter
                Some(price_message) = msg_in_rx.recv() => {
                    self.handle_price_update(price_message).await.map_err(PriceReporterError::ExchangeConnection)?;
                }

                // Dequeue the next job from elsewhere in the local node
                Some(job) = job_receiver.recv() => {
                    if self.config.disabled {
                        warn!("ExternalPriceReporter received job while disabled, ignoring...");
                        continue;
                    }

                    tokio::spawn({
                        let mut self_clone = self.clone();
                        let msg_out_tx = msg_out_tx.clone();
                        async move {
                            if let Err(e) = self_clone.handle_job(job, msg_out_tx).await {
                                error!("Error in ExternalPriceReporter execution loop: {e}");
                            }
                        }.instrument(info_span!("handle_job"))
                    });
                },

                // Await cancellation by the coordinator
                _ = cancel_channel.changed() => {
                    info!("ExternalPriceReporter cancelled, shutting down...");
                    return Err(PriceReporterError::Cancelled("received cancel signal".to_string()));
                }
            }
        }
    }

    /// Spawns the task responsible for handling the websocket connection
    /// with the external price reporter
    fn spawn_ws_handler_loop(
        &self,
    ) -> (UnboundedSender<WebsocketMessage>, UnboundedReceiver<PriceMessage>) {
        let price_reporter_url = self.config.price_reporter_url.clone().unwrap();

        let (msg_out_tx, msg_out_rx) = unbounded_channel();
        let (msg_in_tx, msg_in_rx) = unbounded_channel();

        let subscription_states = self.price_stream_states.clone();

        tokio::spawn(ws_handler_loop(
            price_reporter_url,
            subscription_states,
            msg_out_rx,
            msg_out_tx.clone(),
            msg_in_tx,
        ));

        (msg_out_tx, msg_in_rx)
    }

    /// Handles a price update from the external price reporter
    async fn handle_price_update(
        &self,
        price_message: PriceMessage,
    ) -> Result<(), ExchangeConnectionError> {
        let price = price_message.price;

        // Do not update if the price is default, simply let the price age
        if price == Price::default() {
            return Ok(());
        }

        let (exchange, base_token, quote_token) = parse_topic(&price_message.topic)
            .map_err(err_str!(ExchangeConnectionError::InvalidMessage))?;
        let ts = get_current_time_seconds();

        // Save the price update for the pair on the given exchange
        self.price_stream_states
            .new_price(exchange, base_token.clone(), quote_token.clone(), price, ts)
            .await
            .map_err(err_str!(ExchangeConnectionError::SaveState))?;

        // Compute any high-level price reports subsequent to this update and publish
        // them to the system bus
        self.price_stream_states.publish_price_reports(base_token, quote_token).await;

        Ok(())
    }

    /// Handles a job for the PriceReporter worker.
    pub(super) async fn handle_job(
        &mut self,
        job: PriceReporterJob,
        msg_out_tx: UnboundedSender<WebsocketMessage>,
    ) -> Result<(), PriceReporterError> {
        match job {
            PriceReporterJob::StreamPrice { base_token, quote_token } => {
                self.stream_price(base_token, quote_token, msg_out_tx).await
            },
            PriceReporterJob::PeekPrice { base_token, quote_token, channel } => {
                self.peek_price(base_token, quote_token, channel, msg_out_tx).await
            },
        }
    }

    /// Handler for the StreamPrice job
    async fn stream_price(
        &self,
        base_token: Token,
        quote_token: Token,
        msg_out_tx: UnboundedSender<WebsocketMessage>,
    ) -> Result<(), PriceReporterError> {
        let req_streams = self
            .price_stream_states
            .missing_streams_for_pair(base_token.clone(), quote_token.clone())
            .await;

        for (exchange, base, quote) in req_streams.clone() {
            subscribe_to_price_stream(
                &self.price_stream_states,
                exchange,
                base,
                quote,
                msg_out_tx.clone(),
            )
            .await
            .map_err(PriceReporterError::ExchangeConnection)?;
        }

        self.price_stream_states.register_pairs(base_token, quote_token, &req_streams).await;

        Ok(())
    }

    /// Handler for the PeekPrice job
    async fn peek_price(
        &self,
        base_token: Token,
        quote_token: Token,
        channel: TokioSender<PriceReporterState>,
        msg_out_tx: UnboundedSender<WebsocketMessage>,
    ) -> Result<(), PriceReporterError> {
        // Spawn a task to stream the price. If all of the required streams are already
        // initialized, this will be a no-op.
        tokio::spawn({
            let self_clone = self.clone();
            let base_token = base_token.clone();
            let quote_token = quote_token.clone();
            let msg_out_tx = msg_out_tx.clone();
            async move { self_clone.stream_price(base_token, quote_token, msg_out_tx).await }
        });

        let state = self.price_stream_states.get_state(base_token, quote_token).await;
        channel.send(state).unwrap();

        Ok(())
    }
}

/// The main loop for the websocket handler, responsible for forwarding
/// messages between the external price reporter and the executor, and
/// re-establishing connections indefinitely in case of failure
async fn ws_handler_loop(
    price_reporter_url: Url,
    subscription_states: PriceStreamStatesManager,
    mut msg_out_rx: UnboundedReceiver<WebsocketMessage>,
    msg_out_tx: UnboundedSender<WebsocketMessage>,
    msg_in_tx: UnboundedSender<PriceMessage>,
) -> Result<(), PriceReporterError> {
    let (mut ws_write, mut ws_read) = connect_with_retries(price_reporter_url.clone()).await;

    // Outer loop handles retrying the websocket connection to the external price
    // reporter in case of some failure
    loop {
        // Inner loop handles the actual communication over the websocket
        loop {
            tokio::select! {
                // Forward incoming messages from the external price reporter
                // to the executor
                Some(res) = ws_read.next() => {
                    if let Err(e) = handle_incoming_ws_message(res, &msg_in_tx) {
                        error!("Error handling incoming message from external price reporter: {e}, retrying...");
                        break;
                    }
                }

                // Forward outgoing messages from the executor to the external price reporter
                Some(message) = msg_out_rx.recv() => {
                    if let Err(e) = ws_write.send(Message::Text(serde_json::to_string(&message).unwrap())).await {
                        error!("Error sending message to external price reporter: {e}, retrying...");
                        break;
                    }
                },
            }
        }

        // Breaking from the loop above indicates a failure in the websocket connection.
        // As such, we will have to re-subscribe to all the price streams that
        // were previously subscribed to on the re-established connection, so we
        // enqueue the re-subscription jobs here
        (ws_write, ws_read) = connect_and_resubscribe(
            price_reporter_url.clone(),
            msg_out_tx.clone(),
            &subscription_states,
        )
        .await?;
    }
}

/// Handle an incoming websocket message from the external price reporter
fn handle_incoming_ws_message(
    maybe_msg: Result<Message, tungstenite::Error>,
    msg_in_tx: &UnboundedSender<PriceMessage>,
) -> Result<(), ExchangeConnectionError> {
    match maybe_msg {
        Ok(msg) => {
            if let Message::Text(text) = msg {
                try_handle_price_message(&text, msg_in_tx)?;
            }
            Ok(())
        },

        Err(e) => Err(ExchangeConnectionError::ConnectionHangup(e.to_string())),
    }
}

/// Attempt to process the websocket message as a price message
fn try_handle_price_message(
    msg_text: &str,
    msg_in_tx: &UnboundedSender<PriceMessage>,
) -> Result<(), ExchangeConnectionError> {
    // If receiving a price update from the external price reporter, forward to the
    // executor
    if let Ok(price_message) = serde_json::from_str::<PriceMessage>(msg_text) {
        return msg_in_tx.send(price_message).map_err(err_str!(ExchangeConnectionError::SendError));
    }

    Ok(())
}

/// Subscribes to a price stream for the given exchange and token pair
async fn subscribe_to_price_stream(
    subscription_states: &PriceStreamStatesManager,
    exchange: Exchange,
    base_token: Token,
    quote_token: Token,
    msg_out_tx: UnboundedSender<WebsocketMessage>,
) -> Result<(), ExchangeConnectionError> {
    if subscription_states
        .state_is_initialized(exchange, base_token.clone(), quote_token.clone())
        .await
    {
        return Ok(());
    }

    // Send subscription messages to WS connection
    let topic = format_topic(&exchange, &base_token, &quote_token);
    let message = WebsocketMessage::Subscribe { topic };
    msg_out_tx.send(message).map_err(err_str!(ExchangeConnectionError::SendError))?;

    // Insert the new subscription state
    subscription_states.initialize_state(exchange, base_token, quote_token).await;

    Ok(())
}

/// Await a connection to the external price reporter, and re-subscribe to all
/// the pairs that were previously subscribed to
async fn connect_and_resubscribe(
    price_reporter_url: Url,
    msg_out_tx: UnboundedSender<WebsocketMessage>,
    subscription_states: &PriceStreamStatesManager,
) -> Result<(WsWriteStream, WsReadStream), PriceReporterError> {
    let (ws_write, ws_read) = connect_with_retries(price_reporter_url).await;
    resubscribe_to_prior_streams(msg_out_tx, subscription_states)
        .await
        .map_err(PriceReporterError::ExchangeConnection)?;
    Ok((ws_write, ws_read))
}

/// Attempt to reconnect to the external price reporter,
/// retrying indefinitely until a successful connection is made
async fn connect_with_retries(price_reporter_url: Url) -> (WsWriteStream, WsReadStream) {
    loop {
        match ws_connect(price_reporter_url.clone()).await {
            Ok((write, read)) => return (write, read),
            Err(e) => {
                error!("Error connecting to external price reporter: {e}, retrying...");
                tokio::time::sleep(Duration::from_millis(CONN_RETRY_DELAY_MS)).await;
            },
        }
    }
}

/// Re-send subscription requests to the external price reporter for all the
/// pairs currently indexed in the subscription states, clearing the mapping in
/// the process.
async fn resubscribe_to_prior_streams(
    msg_out_tx: UnboundedSender<WebsocketMessage>,
    subscription_states: &PriceStreamStatesManager,
) -> Result<(), ExchangeConnectionError> {
    // Get the currently subscribed pairs and clear the mapping
    let streams = subscription_states.clear_states().await;

    // Re-send subscription jobs for all the pairs
    for (exchange, base_token, quote_token) in streams {
        subscribe_to_price_stream(
            subscription_states,
            exchange,
            base_token,
            quote_token,
            msg_out_tx.clone(),
        )
        .await?;
    }

    Ok(())
}

/// Format the topic for the given exchange and token pair
fn format_topic(exchange: &Exchange, base_token: &Token, quote_token: &Token) -> String {
    format!("{}-{}-{}", exchange, base_token, quote_token)
}

/// Parse the exchange & pair from a given topic
fn parse_topic(topic: &str) -> Result<(Exchange, Token, Token), ExchangeConnectionError> {
    let parts: Vec<&str> = topic.split('-').collect();
    let exchange =
        Exchange::from_str(parts[0]).map_err(err_str!(ExchangeConnectionError::InvalidMessage))?;
    let base = Token::from_addr(parts[1]);
    let quote = Token::from_addr(parts[2]);

    Ok((exchange, base, quote))
}
