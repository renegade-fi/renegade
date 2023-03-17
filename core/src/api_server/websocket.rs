//! Groups logic for managing websocket connections

use std::net::SocketAddr;

use crossbeam::channel;
use futures::{stream::SplitSink, SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::StreamMap;
use tokio_tungstenite::{accept_async, WebSocketStream};
use tungstenite::Message;

use crate::{
    external_api::websocket::{SubscriptionMessage, SubscriptionResponse},
    price_reporter::{jobs::PriceReporterManagerJob, tokens::Token},
    system_bus::{SystemBus, TopicReader},
    types::{SystemBusMessage, SystemBusMessageWithTopic},
};

use super::{error::ApiServerError, worker::ApiServerConfig};

/// The dummy stream used to seed the websocket subscriptions `StreamMap`
const DUMMY_SUBSCRIPTION_TOPIC: &str = "dummy-topic";

/// A wrapper around request handling and task management
#[derive(Clone)]
pub struct WebsocketServer {
    /// The api server config
    config: ApiServerConfig,
    /// The system bus to receive events on
    system_bus: SystemBus<SystemBusMessage>,
}

impl WebsocketServer {
    /// Create a new websocket server
    pub fn new(config: ApiServerConfig, system_bus: SystemBus<SystemBusMessage>) -> Self {
        Self { config, system_bus }
    }

    /// The main execution loop of the websocket server
    pub async fn execution_loop(self) -> Result<(), ApiServerError> {
        // Bind the server to the given port
        let addr: SocketAddr = format!("0.0.0.0:{:?}", self.config.websocket_port)
            .parse()
            .unwrap();

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|err| ApiServerError::Setup(err.to_string()))?;

        // Await incoming websocket connections
        while let Ok((stream, _)) = listener.accept().await {
            // Create a new handler on this stream
            let self_clone = self.clone();
            tokio::spawn(async move { self_clone.handle_connection(stream).await });
        }

        // If the listener fails, the server has failed
        Err(ApiServerError::WebsocketServerFailure(
            "websocket server spuriously shutdown".to_string(),
        ))
    }

    /// Handle a websocket connection
    async fn handle_connection(&self, stream: TcpStream) -> Result<(), ApiServerError> {
        // Accept the websocket upgrade and split into read/write streams
        let websocket_stream = accept_async(stream)
            .await
            .map_err(|err| ApiServerError::WebsocketServerFailure(err.to_string()))?;
        let (mut write_stream, mut read_stream) = websocket_stream.split();

        // The websocket client will add subscriptions throughout the communication; this tracks the
        // active subscriptions that the local connection has open
        let mut subscriptions = StreamMap::new();

        // The `StreamMap` future implementation will return `Poll::Ready(None)` if no streams are
        // registered, indicating that the mapped stream is empty. We would prefer it to return
        // `Poll::Pending` in this case, so we enter a dummy stream into the map.
        let dummy_reader = self
            .system_bus
            .subscribe(DUMMY_SUBSCRIPTION_TOPIC.to_string());
        subscriptions.insert(DUMMY_SUBSCRIPTION_TOPIC.to_string(), dummy_reader);

        // Begin the listener loop
        loop {
            tokio::select! {
                // Next subscription event from the system bus
                Some((topic, event)) = subscriptions.next() => {
                    self.push_subscribed_event(topic, event, &mut write_stream).await?;
                }

                // Next message from the client side of the websocket
                message = read_stream.next() => {
                    match message {
                        Some(msg) => {
                            if let Err(e) = msg {
                                return Err(ApiServerError::WebsocketServerFailure(e.to_string()));
                            }

                            let message_unwrapped = msg.unwrap();
                            match message_unwrapped {
                                Message::Close(_) => break,
                                _ => {
                                    let bus_clone = self.system_bus.clone();
                                    self.handle_incoming_ws_message(message_unwrapped, &mut subscriptions, &mut write_stream, bus_clone).await?;
                                }
                            };
                        }

                        // None is returned when the connection is closed or a critical error
                        // occurred. In either case the server side may hang up
                        None => break
                    }
                }
            };
        }

        Ok(())
    }

    /// Handle an incoming websocket message
    async fn handle_incoming_ws_message(
        &self,
        message: Message,
        client_subscriptions: &mut StreamMap<String, TopicReader<SystemBusMessage>>,
        write_stream: &mut SplitSink<WebSocketStream<TcpStream>, Message>,
        system_bus: SystemBus<SystemBusMessage>,
    ) -> Result<(), ApiServerError> {
        if let Message::Text(msg_text) = message {
            // Deserialize the message body and dispatch to a handler for a response
            let deserialized: Result<SubscriptionMessage, _> = serde_json::from_str(&msg_text);
            let resp = match deserialized {
                Ok(message_body) => {
                    let response = self
                        .handle_subscription_message(message_body, client_subscriptions, system_bus)
                        .await;
                    let response_serialized = serde_json::to_string(&response)
                        .map_err(|err| ApiServerError::WebsocketServerFailure(err.to_string()))?;

                    Message::Text(response_serialized)
                }

                Err(e) => Message::Text(format!("Invalid request: {}", e)),
            };

            // Write the response onto the websocket
            write_stream
                .send(resp)
                .await
                .map_err(|err| ApiServerError::WebsocketServerFailure(err.to_string()))?;
        }

        Ok(())
    }

    /// Handles an incoming subscribe/unsubscribe message
    async fn handle_subscription_message(
        &self,
        message: SubscriptionMessage,
        client_subscriptions: &mut StreamMap<String, TopicReader<SystemBusMessage>>,
        system_bus: SystemBus<SystemBusMessage>,
    ) -> SubscriptionResponse {
        // Update local subscriptions
        match message {
            SubscriptionMessage::Subscribe { topic } => {
                // Register the topic subscription
                let topic_reader = system_bus.subscribe(topic.clone());
                client_subscriptions.insert(topic.clone(), topic_reader);
                // If the topic is a *-price-report-*, then parse the tokens, send a
                // StartPriceReporter job, and await until confirmed
                let topic_split: Vec<&str> = topic.split('-').collect();
                if topic.contains("-price-report-") && topic_split.len() == 5 {
                    let base_token = Token::from_addr(topic_split[3]);
                    let quote_token = Token::from_addr(topic_split[4]);
                    let (channel_sender, channel_receiver) = channel::unbounded();
                    self.config
                        .price_reporter_work_queue
                        .send(PriceReporterManagerJob::StartPriceReporter {
                            base_token,
                            quote_token,
                            id: None, // TODO: Store an ID for later teardown
                            channel: channel_sender,
                        })
                        .unwrap();
                    channel_receiver.recv().unwrap();
                }
            }
            SubscriptionMessage::Unsubscribe { topic } => {
                client_subscriptions.remove(&topic);
            }
        };

        SubscriptionResponse {
            subscriptions: client_subscriptions
                .keys()
                .cloned()
                .filter(|key| DUMMY_SUBSCRIPTION_TOPIC.to_string().ne(key))
                .collect(),
        }
    }

    /// Push an internal event that the client is subscribed to onto the websocket
    async fn push_subscribed_event(
        &self,
        topic: String,
        event: SystemBusMessage,
        write_stream: &mut SplitSink<WebSocketStream<TcpStream>, Message>,
    ) -> Result<(), ApiServerError> {
        // Serialize the message and push it onto the stream
        let event_serialized =
            serde_json::to_string(&SystemBusMessageWithTopic { topic, event })
                .map_err(|err| ApiServerError::WebsocketServerFailure(err.to_string()))?;
        let message = Message::Text(event_serialized);

        write_stream
            .send(message)
            .await
            .map_err(|err| ApiServerError::WebsocketServerFailure(err.to_string()))?;

        Ok(())
    }
}
