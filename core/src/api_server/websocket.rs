//! Groups logic for managing websocket connections

use std::{net::SocketAddr, sync::Arc};

use futures::{stream::SplitSink, SinkExt, StreamExt};
use hyper::StatusCode;
use matchit::Router;
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::StreamMap;
use tokio_tungstenite::{accept_async, WebSocketStream};
use tracing::log;
use tungstenite::Message;

use crate::{
    external_api::websocket::{SubscriptionMessage, SubscriptionResponse},
    system_bus::TopicReader,
    types::{SystemBusMessage, SystemBusMessageWithTopic, HANDSHAKE_STATUS_TOPIC},
};

use self::handler::{DefaultHandler, WebsocketTopicHandler};

use super::{error::ApiServerError, router::UrlParams, worker::ApiServerConfig};

mod handler;

/// The matchit router with generics specified for websocket use
type WebsocketRouter = Router<Box<dyn WebsocketTopicHandler>>;

/// The dummy stream used to seed the websocket subscriptions `StreamMap`
const DUMMY_SUBSCRIPTION_TOPIC: &str = "dummy-topic";
/// The error message given when an invalid topic is subscribed to
const ERR_INVALID_TOPIC: &str = "invalid topic";

// ----------
// | Topics |
// ----------

/// The handshake topic, events include when a handshake beings and ends
const HANDSHAKE_ROUTE: &str = "/v0/handshake";

// --------------------
// | Websocket Server |
// --------------------

/// A wrapper around request handling and task management
#[derive(Clone)]
pub struct WebsocketServer {
    /// The api server config
    config: ApiServerConfig,
    /// The router that dispatches incoming subscribe/unsubscribe messages
    router: Arc<WebsocketRouter>,
}

impl WebsocketServer {
    /// Create a new websocket server
    pub fn new(config: ApiServerConfig) -> Self {
        let router = Arc::new(Self::setup_routes(&config));
        Self { config, router }
    }

    /// Setup the websocket routes for the server
    #[allow(unused)]
    fn setup_routes(config: &ApiServerConfig) -> WebsocketRouter {
        // TODO: Implement routes
        let mut router = WebsocketRouter::new();

        // The "/v0/handshake" route
        router.insert(
            HANDSHAKE_ROUTE,
            Box::new(DefaultHandler::new_with_remap(
                HANDSHAKE_STATUS_TOPIC.to_string(),
                config.system_bus.clone(),
            )),
        );

        router
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
    ///
    /// Manages subscriptions to internal channels and
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
            .config
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
                                log::error!("error handling websocket connection: {e}");
                                return Err(ApiServerError::WebsocketServerFailure(e.to_string()));
                            }

                            let message_unwrapped = msg.unwrap();
                            match message_unwrapped {
                                Message::Close(_) => break,
                                _ => {
                                    self.handle_incoming_ws_message(message_unwrapped, &mut subscriptions, &mut write_stream).await?;
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

        log::info!("tearing down connection");
        Ok(())
    }

    /// Handle an incoming websocket message
    async fn handle_incoming_ws_message(
        &self,
        message: Message,
        client_subscriptions: &mut StreamMap<String, TopicReader<SystemBusMessage>>,
        write_stream: &mut SplitSink<WebSocketStream<TcpStream>, Message>,
    ) -> Result<(), ApiServerError> {
        if let Message::Text(msg_text) = message {
            // Deserialize the message body and dispatch to a handler for a response
            let deserialized: Result<SubscriptionMessage, _> = serde_json::from_str(&msg_text);
            let resp = match deserialized {
                // Valid message body
                Ok(message_body) => {
                    let response = match self
                        .handle_subscription_message(message_body, client_subscriptions)
                        .await
                    {
                        Ok(resp) => serde_json::to_string(&resp).map_err(|err| {
                            ApiServerError::WebsocketServerFailure(err.to_string())
                        })?,

                        Err(e) => e.to_string(),
                    };

                    Message::Text(response)
                }

                // Respond with an error if deserialization fails
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
    ) -> Result<SubscriptionResponse, ApiServerError> {
        // Update local subscriptions
        match message {
            SubscriptionMessage::Subscribe { topic } => {
                // Find the handler for the given topic
                let (params, route_handler) = self.parse_route_and_params(&topic)?;

                // Register the topic subscription in the system bus and in the stream
                // map that the listener loop polls
                let reader = route_handler.handle_subscribe_message(topic.clone(), &params)?;
                client_subscriptions.insert(topic.clone(), reader);
            }

            SubscriptionMessage::Unsubscribe { topic } => {
                // Parse the route and apply a handler to it
                let (params, route_handler) = self.parse_route_and_params(&topic)?;
                route_handler.handle_unsubscribe_message(topic.clone(), &params)?;

                // Remove the topic subscription from the stream map
                client_subscriptions.remove(&topic);
            }
        };

        Ok(SubscriptionResponse {
            subscriptions: client_subscriptions
                .keys()
                .cloned()
                .filter(|key| DUMMY_SUBSCRIPTION_TOPIC.to_string().ne(key))
                .collect(),
        })
    }

    /// Route a subscribe/unsubscribe message
    fn parse_route_and_params(
        &self,
        topic: &str,
    ) -> Result<(UrlParams, &dyn WebsocketTopicHandler), ApiServerError> {
        // Find the route
        let route = self.router.at(topic).map_err(|_| {
            ApiServerError::HttpStatusCode(StatusCode::NOT_FOUND, ERR_INVALID_TOPIC.to_string())
        })?;

        // Clone the parameters from the route into a hashmap to take ownership
        let mut params = UrlParams::new();
        for (param_name, param_value) in route.params.iter() {
            params.insert(param_name.to_string(), param_value.to_string());
        }

        Ok((params, route.value.as_ref()))
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
