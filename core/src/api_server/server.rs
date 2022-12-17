//! The core logic behind the APIServer's implementation

use hyper::{
    server::{conn::AddrIncoming, Builder},
    Body, Request, Response,
};
use tokio::{runtime::Runtime, task::JoinHandle as TokioJoinHandle};

use crate::state::RelayerState;

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
    pub(super) fn handle_http_req(
        req: Request<Body>,
        global_state: &RelayerState,
    ) -> Result<Response<Body>, ApiServerError> {
        println!(
            "num wallets: {:?}",
            global_state.read_managed_wallets().len()
        );
        Ok(Response::new(Body::from("test response")))
    }
}
