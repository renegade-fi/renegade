//! Defines the ExternalPriceReporterExecutor, a handler that is responsible for
//! executing individual PriceReporterJobs. This is used when the relayer opts
//! for streaming prices from an external price reporter service.

use std::{collections::HashMap, str::FromStr, time::Duration};

use common::{
    default_wrapper::DefaultOption,
    new_async_shared,
    types::{
        exchange::{Exchange, PriceReporterState},
        token::{is_pair_named, Token},
        CancelChannel, Price,
    },
    AsyncShared,
};
use external_api::{
    bus_message::{price_report_topic_name, SystemBusMessage},
    websocket::{SubscriptionResponse, WebsocketMessage},
};
use futures::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use job_types::price_reporter::{PriceReporterJob, PriceReporterQueue, PriceReporterReceiver};
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

use super::{compute_price_reporter_state, get_supported_exchanges, AtomicPriceStreamState};

/// A type alias for the shared state of the price streams
type SubscriptionStates = AsyncShared<HashMap<(Token, Token), AtomicPriceStreamState>>;

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
    subscription_states: SubscriptionStates,
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
            subscription_states: new_async_shared(HashMap::new()),
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
        let price_reporter_job_queue = self.config.job_sender.clone();

        let (msg_out_tx, msg_out_rx) = unbounded_channel();
        let (msg_in_tx, msg_in_rx) = unbounded_channel();

        let subscription_states = self.subscription_states.clone();

        tokio::spawn(ws_handler_loop(
            price_reporter_url,
            subscription_states,
            msg_out_rx,
            msg_in_tx,
            price_reporter_job_queue,
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
        {
            let subscriptions = self.subscription_states.read().await;
            // We unwrap here as we should only get price updates for which we've already
            // mapped a subscription
            subscriptions
                .get(&(base_token.clone(), quote_token.clone()))
                .unwrap()
                .new_price(exchange, price, ts);
        }

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
            PriceReporterJob::StreamPrice { base_token, quote_token } => self
                .subscribe_to_price_stream(base_token, quote_token, msg_out_tx)
                .await
                .map_err(PriceReporterError::ExchangeConnection),
            PriceReporterJob::PeekPrice { base_token, quote_token, channel } => {
                self.peek_price(base_token, quote_token, channel).await
            },
        }
    }

    /// Handler for the StreamPrice job
    async fn subscribe_to_price_stream(
        &mut self,
        base_token: Token,
        quote_token: Token,
        msg_out_tx: UnboundedSender<WebsocketMessage>,
    ) -> Result<(), ExchangeConnectionError> {
        {
            let subscriptions = self.subscription_states.read().await;
            if subscriptions.contains_key(&(base_token.clone(), quote_token.clone())) {
                return Ok(());
            }
        }

        // Send subscription messages to WS connection
        let exchanges = get_supported_exchanges(&base_token, &quote_token, &self.config);
        for exchange in &exchanges {
            let topic = format_topic(exchange, &base_token, &quote_token);
            let message = WebsocketMessage::Subscribe { topic };
            msg_out_tx.send(message).map_err(err_str!(ExchangeConnectionError::SendError))?;
        }

        // Insert the new subscription state
        let mut subscriptions = self.subscription_states.write().await;
        subscriptions.insert(
            (base_token.clone(), quote_token.clone()),
            AtomicPriceStreamState::new_from_exchanges(&exchanges),
        );

        Ok(())
    }

    /// Handler for the PeekPrice job
    async fn peek_price(
        &mut self,
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
        match self.get_latest_price(&Exchange::Binance, &base_token, &quote_token).await {
            None => PriceReporterState::NotEnoughDataReported(0),
            Some((price, ts)) => {
                // Fetch the most recent prices from all other exchanges
                let mut exchange_prices = Vec::new();
                let supported_exchanges =
                    get_supported_exchanges(&base_token, &quote_token, &self.config);
                for exchange in supported_exchanges {
                    if let Some((price, ts)) =
                        self.get_latest_price(&exchange, &base_token, &quote_token).await
                    {
                        exchange_prices.push((exchange, (price, ts)));
                    }
                }

                // Compute the state of the price reporter
                compute_price_reporter_state(base_token, quote_token, price, ts, &exchange_prices)
            },
        }
    }

    /// Get the latest price for the given exchange and token pair
    async fn get_latest_price(
        &self,
        exchange: &Exchange,
        base_token: &Token,
        quote_token: &Token,
    ) -> Option<(Price, u64)> {
        self.subscription_states
            .read()
            .await
            .get(&(base_token.clone(), quote_token.clone()))
            .and_then(|state| state.read_price(exchange))
    }
}

/// The main loop for the websocket handler, responsible for forwarding
/// messages between the external price reporter and the executor, and
/// re-establishing connections indefinitely in case of failure
async fn ws_handler_loop(
    price_reporter_url: Url,
    subscription_states: SubscriptionStates,
    mut msg_out_rx: UnboundedReceiver<WebsocketMessage>,
    msg_in_tx: UnboundedSender<PriceMessage>,
    price_reporter_job_queue: PriceReporterQueue,
) -> Result<(), PriceReporterError> {
    // Outer loop handles retrying the websocket connection to the external price
    // reporter in case of some failure
    loop {
        let (mut ws_write, mut ws_read) = connect_with_retries(price_reporter_url.clone()).await;

        // Re-subscribe to any previously subscribed price streams
        resubscribe_to_prior_streams(&price_reporter_job_queue, &subscription_states).await?;

        // Inner loop handles the actual communication over the websocket
        loop {
            tokio::select! {
                // Forward incoming messages from the external price reporter
                // to the executor
                Some(res) = ws_read.next() => {
                    if let Err(e) = handle_incoming_ws_message(res, &subscription_states, &msg_in_tx).await {
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
    }
}

/// Handle an incoming websocket message from the external price reporter
async fn handle_incoming_ws_message(
    maybe_msg: Result<Message, tungstenite::Error>,
    subscription_states: &SubscriptionStates,
    msg_in_tx: &UnboundedSender<PriceMessage>,
) -> Result<(), ExchangeConnectionError> {
    match maybe_msg {
        Ok(msg) => {
            if let Message::Text(text) = msg {
                try_handle_subscription_response(&text, subscription_states).await?;
                try_handle_price_message(&text, msg_in_tx)?;
            }
            Ok(())
        },

        Err(e) => Err(ExchangeConnectionError::ConnectionHangup(e.to_string())),
    }
}

/// Attempt to process the websocket message as a subscription response
async fn try_handle_subscription_response(
    msg_text: &str,
    subscription_states: &SubscriptionStates,
) -> Result<(), ExchangeConnectionError> {
    // If receiving a subscription response from the price reporter,
    // log the subscribed topics (exchange, base, quote)
    if let Ok(subscription_response) = serde_json::from_str::<SubscriptionResponse>(msg_text) {
        return log_subscribed_exchanges(&subscription_response, subscription_states).await;
    }

    Ok(())
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

/// Re-send subscription jobs to the price reporter for all the pairs currently
/// indexed in the subscription states, clearing the mapping in the process.
async fn resubscribe_to_prior_streams(
    price_reporter_job_queue: &PriceReporterQueue,
    subscription_states: &SubscriptionStates,
) -> Result<(), PriceReporterError> {
    // Get the currently subscribed pairs and clear the mapping
    let pairs = {
        let mut subscriptions = subscription_states.write().await;
        let pairs: Vec<(Token, Token)> = subscriptions.keys().cloned().collect();
        subscriptions.clear();
        pairs
    };

    // Re-send subscription jobs for all the pairs
    for (base_token, quote_token) in pairs {
        price_reporter_job_queue
            .send(PriceReporterJob::StreamPrice { base_token, quote_token })
            .map_err(err_str!(PriceReporterError::ReSubscription))?;
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

/// Log the exchanges that the price reporter has subscribed to
async fn log_subscribed_exchanges(
    subscription_response: &SubscriptionResponse,
    subscription_states: &AsyncShared<HashMap<(Token, Token), AtomicPriceStreamState>>,
) -> Result<(), ExchangeConnectionError> {
    // Iterate over the subscriptions, parse the topic, and filter for those
    // which are not already present in the subscription states

    let subscriptions = subscription_response
        .subscriptions
        .iter()
        .map(|t| parse_topic(t))
        .collect::<Result<Vec<(Exchange, Token, Token)>, ExchangeConnectionError>>()?;

    for (exchange, base, quote) in subscriptions {
        if is_new_subscription(subscription_states, &exchange, &base, &quote).await {
            info!(
                "Now subscribed to {}-{} pair on {} from external price reporter",
                base, quote, exchange
            );
        }
    }

    Ok(())
}

/// Check if the given subscription is a new subscription
async fn is_new_subscription(
    subscription_states: &SubscriptionStates,
    exchange: &Exchange,
    base: &Token,
    quote: &Token,
) -> bool {
    let current_subscriptions = subscription_states.read().await;

    // If the we have no subscriptions at all for the pair it must be a new
    // subscription
    if !current_subscriptions.contains_key(&(base.clone(), quote.clone())) {
        return true;
    }

    // If we have a subscription for the pair, but the price for the given exchange
    // is default, it must be a new subscription
    current_subscriptions
        .get(&(base.clone(), quote.clone()))
        .unwrap()
        .read_price(exchange)
        .unwrap_or_default()
        .0
        == Price::default()
}
