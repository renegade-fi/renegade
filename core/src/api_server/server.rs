//! The core logic behind the APIServer's implementation

use hyper::server::{conn::AddrIncoming, Builder};
use tokio::{runtime::Runtime, task::JoinHandle as TokioJoinHandle};

use super::error::ApiServerError;

/// Accepts inbound HTTP requests and websocket subscriptions and
/// serves requests from those connections
///
/// Clients of this server might be traders looking to manage their
/// trades, view live execution events, etc
pub struct ApiServer {
    /// The builder for the HTTP server before it begins serving; wrapped in
    /// an option to allow the worker threads to take ownership of the value
    pub(super) http_server_builder: Option<Builder<AddrIncoming>>,
    /// The join handle for the http server
    pub(super) http_server_join_handle: Option<TokioJoinHandle<ApiServerError>>,
    /// The tokio runtime that the http server runs inside of
    pub(super) http_server_runtime: Option<Runtime>,
}
