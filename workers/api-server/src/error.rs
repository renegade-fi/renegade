//! Defines error types that occur in the ApiServer

use std::fmt::{Display, Formatter, Result as FmtResult};

use hyper::{Body, Response, StatusCode};

use super::router::{build_500_response, build_response_from_status_code};

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

impl From<ApiServerError> for Response<Body> {
    fn from(err: ApiServerError) -> Self {
        match err {
            ApiServerError::HttpStatusCode(status, message) => {
                build_response_from_status_code(status, message)
            },
            _ => build_500_response(err.to_string()),
        }
    }
}
