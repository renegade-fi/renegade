//! The core logic behind the APIServer's implementation

use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};

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
use tokio_tungstenite::{accept_async, WebSocketStream};
use tungstenite::Message;

use crate::{
    api::{
        http::{GetReplicasRequest, GetReplicasResponse},
        websocket::{SubscriptionMessage, SubscriptionResponse},
    },
    state::RelayerState,
};

use super::{
    error::ApiServerError,
    routes::{Router, TypedHandler},
    worker::ApiServerConfig,
};

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
    pub(super) async fn websocket_execution_loop(addr: SocketAddr) -> Result<(), ApiServerError> {
        // Bind to the addr
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|err| ApiServerError::Setup(err.to_string()))?;

        // Loop over incoming streams
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(Self::serve_websocket(stream));
        }

        // If the listener fails, the server has failed
        Err(ApiServerError::WebsocketServerFailure(
            "websocket server spuriously shutdown".to_string(),
        ))
    }

    /// Serve a websocket connection from a front end
    async fn serve_websocket(incoming_stream: TcpStream) -> Result<(), ApiServerError> {
        // Accept the websocket upgrade and split into read/write streams
        let websocket_stream = accept_async(incoming_stream)
            .await
            .map_err(|err| ApiServerError::WebsocketHandlerFailure(err.to_string()))?;
        let (mut write_stream, mut read_stream) = websocket_stream.split();

        // The websocket client will add subscriptions throughout the communication; this tracks the
        // active subscriptions that the local connection has open
        let mut subscriptions: HashSet<String> = HashSet::new();

        // Send test messages in a loop
        let mut interval = tokio::time::interval(Duration::from_millis(5000));
        let message = Message::Text("test".to_string());
        loop {
            tokio::select! {
                // Read side
                message = read_stream.next() => {
                    match message {
                        Some(msg) => {
                            if let Err(e) = msg {
                                return Err(ApiServerError::WebsocketHandlerFailure(e.to_string()));
                            }

                            let message_unwrapped = msg.unwrap();
                            match message_unwrapped {
                                Message::Close(_) => break,
                                _ => Self::handle_incoming_ws_message(message_unwrapped, &mut subscriptions, &mut write_stream).await?,
                            };
                        }

                        // None is returned when the connection is closed or a critical error
                        // occured. In either case the server side may hang up
                        None => break
                    }
                }

                // Sender push side
                _ = interval.tick() => {
                    write_stream.send(message.clone()).await.unwrap();
                }
            }
        }

        println!("Finished connection...\n\n");
        Ok(())
    }

    /// Handle an incoming websocket message
    async fn handle_incoming_ws_message(
        message: Message,
        client_subscriptions: &mut HashSet<String>,
        write_stream: &mut SplitSink<WebSocketStream<TcpStream>, Message>,
    ) -> Result<(), ApiServerError> {
        if let Message::Text(msg_text) = message {
            // Deserialize the message body and dispatch to a handler for a response
            let deserialized: Result<SubscriptionMessage, _> = serde_json::from_str(&msg_text);
            let resp = match deserialized {
                Ok(message_body) => {
                    let response =
                        Self::handle_subscription_message(message_body, client_subscriptions);
                    let response_ser = serde_json::to_string(&response)
                        .map_err(|err| ApiServerError::WebsocketHandlerFailure(err.to_string()))?;

                    Message::Text(response_ser)
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
    fn handle_subscription_message(
        message: SubscriptionMessage,
        client_subscriptions: &mut HashSet<String>,
    ) -> SubscriptionResponse {
        // Update local subscriptions
        match message {
            SubscriptionMessage::Subscribe { topic } => client_subscriptions.insert(topic),
            SubscriptionMessage::Unsubscribe { topic } => client_subscriptions.remove(&topic),
        };

        SubscriptionResponse {
            subscriptions: client_subscriptions.iter().cloned().collect(),
        }
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
