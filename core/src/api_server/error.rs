//! Defines error types that occur in the ApiServer

use std::fmt::{Display, Formatter, Result as FmtResult};

use hyper::StatusCode;

/// The error type for errors that occur during ApiServer execution
#[derive(Clone, Debug)]
pub enum ApiServerError {
    /// An http error code, should be forwarded as a response
    HttpStatusCode(StatusCode, String),
    /// HTTP server has failed
    HttpServerFailure(String),
    /// Error setting up the API server
    Setup(String),
    /// Websocket server has failed
    WebsocketServerFailure(String),
}

impl Display for ApiServerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{:?}", self)
    }
}
