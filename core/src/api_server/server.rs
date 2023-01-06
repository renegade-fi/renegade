//! The core logic behind the APIServer's implementation

use std::{net::SocketAddr, sync::Arc};

use crossbeam::channel::{self, Sender};
use futures::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use hyper::{
    server::{conn::AddrIncoming, Builder},
    Body, Method, Request, Response,
};
use tokio::{
    net::{TcpListener, TcpStream},
    runtime::Runtime,
    task::JoinHandle as TokioJoinHandle,
};
use tokio_stream::StreamMap;
use tokio_tungstenite::{accept_async, WebSocketStream};
use tungstenite::Message;

use crate::{
    api::{
        http::{GetReplicasRequest, GetReplicasResponse},
        websocket::{SubscriptionMessage, SubscriptionResponse},
    },
    price_reporter::{jobs::PriceReporterManagerJob, tokens::Token},
    state::RelayerState,
    system_bus::{SystemBus, TopicReader},
    types::SystemBusMessage,
};

use super::{
    error::ApiServerError,
    routes::{Router, TypedHandler},
    worker::ApiServerConfig,
};

/// The dummy stream used to seed the websocket subscriptions `StreamMap`
const DUMMY_SUBSCRIPTION_TOPIC: &str = "dummy-topic";

/// Accepts inbound HTTP requests and websocket subscriptions and
/// serves requests from those connections
///
/// Clients of this server might be traders looking to manage their
/// trades, view live execution events, etc
pub struct ApiServer {
    /// The config passed to the worker
    pub(super) config: ApiServerConfig,
    /// The builder for the HTTP server before it begins serving; wrapped in
    /// an option to allow the worker threads to take ownership of the value
    pub(super) http_server_builder: Option<Builder<AddrIncoming>>,
    /// The join handle for the http server
    pub(super) http_server_join_handle: Option<TokioJoinHandle<ApiServerError>>,
    /// The join handle for the websocket server
    pub(super) websocket_server_join_handle: Option<TokioJoinHandle<ApiServerError>>,
    /// The tokio runtime that the http server runs inside of
    pub(super) server_runtime: Option<Runtime>,
}

impl ApiServer {
    /// The main execution loop for the websocket server
    pub(super) async fn websocket_execution_loop(
        addr: SocketAddr,
        price_reporter_worker_sender: Sender<PriceReporterManagerJob>,
        system_bus: SystemBus<SystemBusMessage>,
    ) -> Result<(), ApiServerError> {
        // Bind to the addr
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|err| ApiServerError::Setup(err.to_string()))?;

        // Loop over incoming streams
        while let Ok((stream, _)) = listener.accept().await {
            // Create a new handler on this stream
            let handler = WebsocketHandler::new(
                stream,
                price_reporter_worker_sender.clone(),
                system_bus.clone(),
            );
            tokio::spawn(handler.start());
        }

        // If the listener fails, the server has failed
        Err(ApiServerError::WebsocketServerFailure(
            "websocket server spuriously shutdown".to_string(),
        ))
    }

    /// Sets up the routes that the API service exposes in the router
    pub(super) fn setup_routes(router: &mut Router, global_state: RelayerState) {
        // The "/replicas" route
        router.add_route(
            Method::POST,
            "/replicas".to_string(),
            ReplicasHandler::new(global_state),
        )
    }

    /// Handles an incoming HTTP request
    pub(super) async fn handle_http_req(req: Request<Body>, router: Arc<Router>) -> Response<Body> {
        // Route the request
        router
            .handle_req(req.method().to_owned(), req.uri().path().to_string(), req)
            .await
    }
}

/// Handler for connections to the websocket server
#[derive(Debug)]
pub struct WebsocketHandler {
    /// The TCP stream underlying the websocket that has been opened
    tcp_stream: Option<TcpStream>,
    /// The worker job queue for the PriceReporterManager
    price_reporter_worker_sender: Sender<PriceReporterManagerJob>,
    /// The system bus to recieve events on
    system_bus: SystemBus<SystemBusMessage>,
}

impl WebsocketHandler {
    /// Create a new websocket handler
    pub fn new(
        inbound_stream: TcpStream,
        price_reporter_worker_sender: Sender<PriceReporterManagerJob>,
        system_bus: SystemBus<SystemBusMessage>,
    ) -> Self {
        Self {
            tcp_stream: Some(inbound_stream),
            price_reporter_worker_sender,
            system_bus,
        }
    }

    /// Start the websocket handler and run it
    ///
    /// Consumes the reference to the handler
    pub async fn start(mut self) -> Result<(), ApiServerError> {
        // Accept the websocket upgrade and split into read/write streams
        let tcp_stream = self.tcp_stream.take().unwrap();
        let websocket_stream = accept_async(tcp_stream)
            .await
            .map_err(|err| ApiServerError::WebsocketHandlerFailure(err.to_string()))?;
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
                Some((_, event)) = subscriptions.next() => {
                    self.push_subscribed_event(event, &mut write_stream).await?;
                }

                // Next message from the client side of the websocket
                message = read_stream.next() => {
                    match message {
                        Some(msg) => {
                            if let Err(e) = msg {
                                return Err(ApiServerError::WebsocketHandlerFailure(e.to_string()));
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
                        // occured. In either case the server side may hang up
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
                    let response = self.handle_subscription_message(
                        message_body,
                        client_subscriptions,
                        system_bus,
                    ).await;
                    let response_serialized = serde_json::to_string(&response)
                        .map_err(|err| ApiServerError::WebsocketHandlerFailure(err.to_string()))?;

                    Message::Text(response_serialized)
                }

                Err(e) => Message::Text(format!("Invalid request: {}", e)),
            };

            // Write the response onto the websocket
            write_stream
                .send(resp)
                .await
                .map_err(|err| ApiServerError::WebsocketHandlerFailure(err.to_string()))?;
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
                // If the topic is a price-report-*, then parse the tokens, send a
                // StartPriceReporter job, and await until confirmed
                let topic_split: Vec<&str> = topic.split('-').collect();
                if topic.starts_with("price-report-") && topic_split.len() == 4 {
                    let base_token = Token::from_addr(topic_split[2]);
                    let quote_token = Token::from_addr(topic_split[3]);
                    let (channel_sender, channel_receiver) = channel::unbounded();
                    self.price_reporter_worker_sender
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
        event: SystemBusMessage,
        write_stream: &mut SplitSink<WebSocketStream<TcpStream>, Message>,
    ) -> Result<(), ApiServerError> {
        // Serialize the message and push it onto the stream
        let event_serialized = serde_json::to_string(&event)
            .map_err(|err| ApiServerError::WebsocketHandlerFailure(err.to_string()))?;
        let message = Message::Text(event_serialized);

        write_stream
            .send(message)
            .await
            .map_err(|err| ApiServerError::WebsocketHandlerFailure(err.to_string()))?;

        Ok(())
    }
}

/// Handler for the replicas route, returns the number of replicas a given wallet has
#[derive(Clone, Debug)]
pub struct ReplicasHandler {
    /// The global state of the relayer, used to query information for requests
    global_state: RelayerState,
}

impl ReplicasHandler {
    /// Create a new handler for "/replicas"
    fn new(global_state: RelayerState) -> Self {
        Self { global_state }
    }
}

impl TypedHandler for ReplicasHandler {
    type Request = GetReplicasRequest;
    type Response = GetReplicasResponse;
    type Error = ApiServerError;

    fn handle_typed(&self, req: Self::Request) -> Result<Self::Response, Self::Error> {
        let replicas = if let Some(wallet_info) =
            self.global_state.read_managed_wallets().get(&req.wallet_id)
        {
            wallet_info.metadata.replicas.clone().into_iter().collect()
        } else {
            vec![]
        };

        Ok(GetReplicasResponse { replicas })
    }
}
