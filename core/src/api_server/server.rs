//! The core logic behind the APIServer's implementation

use hyper::{
    server::{conn::AddrIncoming, Builder},
    Body, Method, Request, Response, StatusCode,
};
use tokio::{runtime::Runtime, task::JoinHandle as TokioJoinHandle};

use crate::{
    api::http::{GetReplicasRequest, GetReplicasResponse},
    state::RelayerState,
};

use super::{error::ApiServerError, worker::ApiServerConfig};

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
    /// Handles an incoming HTTP request
    pub(super) async fn handle_http_req(
        req: Request<Body>,
        global_state: &RelayerState,
    ) -> Result<Response<Body>, ApiServerError> {
        match (req.method(), req.uri().path()) {
            (&Method::POST, "/replicas") => {
                Ok(Self::handle_get_wallet_info(req, global_state).await)
            }
            _ => Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::empty())
                .unwrap()),
        }
    }

    /// Handles a request to "/replicas"
    ///
    /// Request is of the form { wallet_id: uuid }
    ///
    /// Returns the replicas of a wallet with the fields
    ///     - wallet_id: <uuid>
    ///     - replicas: [uuid]
    async fn handle_get_wallet_info(
        req: Request<Body>,
        global_state: &RelayerState,
    ) -> Response<Body> {
        let body = hyper::body::to_bytes(req.into_body()).await;
        if body.is_err() {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::empty())
                .unwrap();
        }

        let deserialized = serde_json::from_slice(&body.unwrap());
        if deserialized.is_err() {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::empty())
                .unwrap();
        }

        let req_body: GetReplicasRequest = deserialized.unwrap();
        let replicas = if let Some(wallet_info) =
            global_state.read_managed_wallets().get(&req_body.wallet_id)
        {
            wallet_info.metadata.replicas.clone().into_iter().collect()
        } else {
            vec![]
        };

        let resp = GetReplicasResponse { replicas };
        Response::new(Body::from(serde_json::to_vec(&resp).unwrap()))
    }
}
