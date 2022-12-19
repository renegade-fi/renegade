//! Defines error types that occur in the ApiServer

use std::fmt::{Display, Formatter, Result as FmtResult};

/// The error type for errors that occur during ApiServer execution
#[derive(Clone, Debug)]
pub enum ApiServerError {
    /// Error setting up the API server
    Setup(String),
    /// HTTP server has failed
    HttpServerFailure(String),
    /// A failure while handling a websocket connection
    WebsocketHandlerFailure(String),
    /// Websocket server has failed
    WebsocketServerFailure(String),
}

impl Display for ApiServerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{:?}", self)
    }
}
