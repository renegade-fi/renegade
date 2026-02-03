//! Groups logic for managing websocket connections

use std::{net::SocketAddr, sync::Arc};

use constants::in_bootstrap_mode;
use external_api::{
    types::ServerWebsocketMessage,
    websocket::{ClientWebsocketMessage, SubscriptionResponse, WebsocketMessage},
};
use futures::{SinkExt, StreamExt, stream::SplitSink};
use hyper::{HeaderMap, http::HeaderValue};
use matchit::Router;
use system_bus::{SystemBusMessage, TopicReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::StreamMap;
use tokio_tungstenite::{WebSocketStream, accept_async};
use tungstenite::Message;

use super::conversion::system_bus_message_to_websocket_body;

use crate::error::ApiServerError;
use crate::param_parsing::parse_account_id_from_params;
use crate::router::UrlParams;
use crate::worker::ApiServerConfig;
use crate::{
    auth::{AuthMiddleware, AuthType},
    error::{bad_request, not_found},
};

use super::handler::{DefaultHandler, WebsocketTopicHandler};

/// The matchit router with generics specified for websocket use
type WebsocketRouter = Router<Box<dyn WebsocketTopicHandler>>;

/// The dummy stream used to seed the websocket subscriptions `StreamMap`
const DUMMY_SUBSCRIPTION_TOPIC: &str = "dummy-topic";
/// The error message given when an invalid topic is subscribed to
const ERR_INVALID_TOPIC: &str = "invalid topic";
/// The error message given when a header map cannot be parsed for a request
const ERR_HEADER_PARSE: &str = "error parsing headers";

// ----------
// | Topics |
// ----------

/// The handshake topic, events include when a handshake beings and ends
const HANDSHAKE_ROUTE: &str = "/v2/handshake";
/// The wallet topic, events about wallet updates are streamed here
const WALLET_ROUTE: &str = "/v2/wallet/:wallet_id";
/// The wallet order status topic, streams events about wallet's orders
const WALLET_ORDERS_ROUTE: &str = "/v2/wallet/:wallet_id/order-status";
/// The price report topic, events about price updates are streamed
const PRICE_REPORT_ROUTE: &str = "/v2/price_report/:source/:base/:quote";
/// The order book topic, streams events about known network orders
const ORDER_BOOK_ROUTE: &str = "/v2/order_book";
/// The network topic, streams events about network peers
const NETWORK_INFO_ROUTE: &str = "/v2/network";
/// The task status topic, streams information about task statuses
const TASK_STATUS_ROUTE: &str = "/v2/tasks/:task_id";
/// The task history topic, streams information about historical tasks
const TASK_HISTORY_ROUTE: &str = "/v2/wallet/:wallet_id/task-history";
/// The admin order updates topic, streams granular order updates for all
/// accounts
const ADMIN_ORDER_UPDATES_ROUTE: &str = "/v2/admin/orders";
/// The admin balance updates topic, streams granular balance updates for all
/// accounts
const ADMIN_BALANCE_UPDATES_ROUTE: &str = "/v2/admin/balances";

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
    /// The authentication middleware
    auth_middleware: AuthMiddleware,
}

impl WebsocketServer {
    /// Create a new websocket server
    pub fn new(config: ApiServerConfig) -> Self {
        let router = Arc::new(Self::setup_routes(&config));
        let auth_middleware = AuthMiddleware::new(config.admin_api_key, config.state.clone());
        Self { config, router, auth_middleware }
    }

    /// Setup the websocket routes for the server
    fn setup_routes(config: &ApiServerConfig) -> WebsocketRouter {
        let mut router = WebsocketRouter::new();

        // The "/v2/admin/orders" route
        router
            .insert(
                ADMIN_ORDER_UPDATES_ROUTE,
                Box::new(DefaultHandler::new_with_remap(
                    AuthType::Admin,
                    system_bus::ADMIN_ORDER_UPDATES_TOPIC.to_string(),
                    config.system_bus.clone(),
                )),
            )
            .expect("failed to insert admin order updates route");

        // The "/v2/admin/balances" route
        router
            .insert(
                ADMIN_BALANCE_UPDATES_ROUTE,
                Box::new(DefaultHandler::new_with_remap(
                    AuthType::Admin,
                    system_bus::ADMIN_BALANCE_UPDATES_TOPIC.to_string(),
                    config.system_bus.clone(),
                )),
            )
            .expect("failed to insert admin balance updates route");

        router
    }

    /// The main execution loop of the websocket server
    pub async fn execution_loop(self) -> Result<(), ApiServerError> {
        // Bind the server to the given port
        let addr: SocketAddr = format!("0.0.0.0:{:?}", self.config.websocket_port).parse().unwrap();

        let listener =
            TcpListener::bind(addr).await.map_err(|err| ApiServerError::Setup(err.to_string()))?;

        // Await incoming websocket connections
        while let Ok((stream, _)) = listener.accept().await {
            // Create a new handler on this stream
            let self_clone = self.clone();
            #[allow(clippy::redundant_async_block)]
            tokio::spawn(async move { self_clone.handle_connection(stream).await });
        }

        // If the listener fails, the server has failed
        Err(ApiServerError::WebsocketServerFailure(
            "websocket server spuriously shutdown".to_string(),
        ))
    }

    /// Handle a websocket connection
    ///
    /// Manages subscriptions to internal channels and dispatches
    /// subscribe/unsubscribe requests
    async fn handle_connection(&self, stream: TcpStream) -> Result<(), ApiServerError> {
        // Ignore connections in bootstrap mode
        if in_bootstrap_mode() {
            return Ok(());
        }

        // Accept the websocket upgrade and split into read/write streams
        let websocket_stream = accept_async(stream)
            .await
            .map_err(|err| ApiServerError::WebsocketServerFailure(err.to_string()))?;
        let (mut write_stream, mut read_stream) = websocket_stream.split();

        // The websocket client will add subscriptions throughout the communication;
        // this tracks the active subscriptions that the local connection has
        // open
        let mut subscriptions = StreamMap::new();

        // The `StreamMap` future implementation will return `Poll::Ready(None)` if no
        // streams are registered, indicating that the mapped stream is empty.
        // We would prefer it to return `Poll::Pending` in this case, so we
        // enter a dummy stream into the map.
        let dummy_reader = self.config.system_bus.subscribe(DUMMY_SUBSCRIPTION_TOPIC.to_string());
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
            let deserialized: Result<ClientWebsocketMessage, _> = serde_json::from_str(&msg_text);
            let resp = match deserialized {
                // Valid message body
                Ok(message) => {
                    let response =
                        match self.handle_subscription_message(message, client_subscriptions).await
                        {
                            Ok(resp) => serde_json::to_string(&resp).map_err(|err| {
                                ApiServerError::WebsocketServerFailure(err.to_string())
                            })?,

                            Err(e) => e.to_string(),
                        };

                    Message::Text(response)
                },

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
        message: ClientWebsocketMessage,
        client_subscriptions: &mut StreamMap<String, TopicReader<SystemBusMessage>>,
    ) -> Result<SubscriptionResponse, ApiServerError> {
        // Update local subscriptions
        match message.body {
            WebsocketMessage::Subscribe { ref topic } => {
                // Find the handler for the given topic
                let (params, route_handler) = self.parse_route_and_params(topic)?;

                // Validate auth
                self.authenticate_subscription(route_handler.auth_type(), topic, &params, &message)
                    .await?;

                // Register the topic subscription in the system bus and in the stream
                // map that the listener loop polls
                let reader = route_handler.handle_subscribe_message(topic.clone(), &params).await?;
                client_subscriptions.insert(topic.clone(), reader);
            },

            WebsocketMessage::Unsubscribe { topic } => {
                // Parse the route and apply a handler to it
                let (params, route_handler) = self.parse_route_and_params(&topic)?;
                route_handler.handle_unsubscribe_message(topic.clone(), &params).await?;

                // Remove the topic subscription from the stream map
                client_subscriptions.remove(&topic);
            },
        };

        Ok(SubscriptionResponse {
            subscriptions: client_subscriptions
                .keys()
                .filter(|&key| DUMMY_SUBSCRIPTION_TOPIC.to_string().ne(key))
                .cloned()
                .collect(),
        })
    }

    /// Route a subscribe/unsubscribe message
    fn parse_route_and_params(
        &self,
        topic: &str,
    ) -> Result<(UrlParams, &dyn WebsocketTopicHandler), ApiServerError> {
        // Find the route
        let route = self.router.at(topic).map_err(|_| not_found(ERR_INVALID_TOPIC.to_string()))?;

        // Clone the parameters from the route into a hashmap to take ownership
        let mut params = UrlParams::new();
        for (param_name, param_value) in route.params.iter() {
            params.insert(param_name.to_string(), param_value.to_string());
        }

        Ok((params, route.value.as_ref()))
    }

    /// Authenticate a websocket subscription
    async fn authenticate_subscription(
        &self,
        auth_type: AuthType,
        topic: &str,
        params: &UrlParams,
        message: &ClientWebsocketMessage,
    ) -> Result<(), ApiServerError> {
        if matches!(auth_type, AuthType::None) {
            return Ok(());
        }

        let headers: HeaderMap<HeaderValue> = HeaderMap::try_from(&message.headers)
            .map_err(|_| bad_request(ERR_HEADER_PARSE.to_string()))?;

        // Serialize the body to bytes
        let body_serialized =
            serde_json::to_vec(&message.body).expect("re-serialization should not fail");

        match auth_type {
            AuthType::Account => {
                // Parse the account ID from the params
                let account_id = parse_account_id_from_params(params)?;
                self.auth_middleware
                    .authenticate_account_request(account_id, topic, &headers, &body_serialized)
                    .await
            },
            AuthType::Admin => {
                self.auth_middleware.authenticate_admin_request(topic, &headers, &body_serialized)
            },
            AuthType::None => unreachable!(),
        }
    }

    /// Push an internal event that the client is subscribed to onto the
    /// websocket
    async fn push_subscribed_event(
        &self,
        topic: String,
        event: SystemBusMessage,
        write_stream: &mut SplitSink<WebSocketStream<TcpStream>, Message>,
    ) -> Result<(), ApiServerError> {
        // Convert the system bus message to a websocket message body
        let body = system_bus_message_to_websocket_body(event);

        // Serialize and push onto the stream
        let ws_message = ServerWebsocketMessage { topic, body };
        let event_serialized = serde_json::to_string(&ws_message)
            .map_err(|err| ApiServerError::WebsocketServerFailure(err.to_string()))?;
        let message = Message::Text(event_serialized);

        write_stream
            .send(message)
            .await
            .map_err(|err| ApiServerError::WebsocketServerFailure(err.to_string()))
    }
}
