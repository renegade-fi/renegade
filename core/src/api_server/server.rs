//! The core logic behind the APIServer's implementation

use std::sync::Arc;

use hyper::{
    server::{conn::AddrIncoming, Builder},
    Body, Method, Request, Response,
};
use tokio::{runtime::Runtime, task::JoinHandle as TokioJoinHandle};

use crate::{
    api::http::{GetReplicasRequest, GetReplicasResponse},
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
    /// The tokio runtime that the http server runs inside of
    pub(super) http_server_runtime: Option<Runtime>,
}

impl ApiServer {
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
