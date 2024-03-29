//! Defines the ExternalPriceReporterExecutor, a handler that is responsible for
//! executing individual PriceReporterJobs. This is used when the relayer opts
//! for streaming prices from an external price reporter service.

use std::{str::FromStr, time::Duration};

use common::{
    default_wrapper::DefaultOption,
    types::{
        exchange::{Exchange, PriceReporterState},
        token::{default_exchange_stable, is_pair_named, Token},
        CancelChannel, Price,
    },
};
use external_api::{
    bus_message::{price_report_topic_name, SystemBusMessage},
    websocket::WebsocketMessage,
};
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

use super::{
    compute_price_reporter_state, eligible_for_stable_quote_conversion, get_supported_exchanges,
    SharedPriceStates,
};

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
    /// The map between (base, quote) pairs and the latest
    /// timestamped prices for those pairs across the exchanges
    subscription_states: SharedPriceStates,
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
            subscription_states: SharedPriceStates::new(),
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

        let subscription_states = self.subscription_states.clone();

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
        self.subscription_states
            .new_price(exchange, base_token.clone(), quote_token.clone(), price, ts)
            .await
            .map_err(err_str!(ExchangeConnectionError::SaveState))?;

        // Compute the high-level price report for the pair
        let topic_name = price_report_topic_name(&base_token, &quote_token);
        if self.config.system_bus.has_listeners(&topic_name) {
            if let PriceReporterState::Nominal(report) =
                self.get_state(base_token, quote_token).await
            {
                self.config.system_bus.publish(topic_name, SystemBusMessage::PriceReport(report));
            }
        }

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
                self.peek_price(base_token, quote_token, channel).await
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
        let exchanges = get_supported_exchanges(&base_token, &quote_token, &self.config);
        for exchange in exchanges {
            // If the quote is a stablecoin (and the base is not), we may invoke price
            // conversion through the default stable quote for the exchange
            let subs = if eligible_for_stable_quote_conversion(&base_token, &quote_token, &exchange)
            {
                let default_stable = default_exchange_stable(&exchange);
                vec![
                    (base_token.clone(), default_stable.clone()),
                    (quote_token.clone(), default_stable),
                ]
            } else {
                vec![(base_token.clone(), quote_token.clone())]
            };

            for (base, quote) in subs {
                subscribe_to_price_stream(
                    &self.subscription_states,
                    exchange,
                    base,
                    quote,
                    msg_out_tx.clone(),
                )
                .await
                .map_err(PriceReporterError::ExchangeConnection)?;
            }
        }

        Ok(())
    }

    /// Handler for the PeekPrice job
    async fn peek_price(
        &self,
        base_token: Token,
        quote_token: Token,
        channel: TokioSender<PriceReporterState>,
    ) -> Result<(), PriceReporterError> {
        // TODO: Get-or-create price stream subscription
        let state = self.get_state(base_token, quote_token).await;
        channel.send(state).unwrap();

        Ok(())
    }

    /// Get the state of the price reporter for the given token pair
    async fn get_state(&self, base_token: Token, quote_token: Token) -> PriceReporterState {
        // We don't currently support unnamed pairs
        if !is_pair_named(&base_token, &quote_token) {
            return PriceReporterState::UnsupportedPair(base_token, quote_token);
        }

        // Fetch the most recent Binance price
        match self
            .subscription_states
            .get_latest_price(Exchange::Binance, &base_token, &quote_token)
            .await
        {
            None => PriceReporterState::NotEnoughDataReported(0),
            Some((price, ts)) => {
                // Fetch the most recent prices from all other exchanges
                let mut exchange_prices = Vec::new();
                let supported_exchanges =
                    get_supported_exchanges(&base_token, &quote_token, &self.config);
                for exchange in supported_exchanges {
                    if let Some((price, ts)) = self
                        .subscription_states
                        .get_latest_price(exchange, &base_token, &quote_token)
                        .await
                    {
                        exchange_prices.push((exchange, (price, ts)));
                    }
                }

                // Compute the state of the price reporter
                compute_price_reporter_state(base_token, quote_token, price, ts, &exchange_prices)
            },
        }
    }
}

/// The main loop for the websocket handler, responsible for forwarding
/// messages between the external price reporter and the executor, and
/// re-establishing connections indefinitely in case of failure
async fn ws_handler_loop(
    price_reporter_url: Url,
    subscription_states: SharedPriceStates,
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
    subscription_states: &SharedPriceStates,
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
    subscription_states: &SharedPriceStates,
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
    subscription_states: &SharedPriceStates,
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
