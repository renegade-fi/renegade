//! Defines error types that occur in the ApiServer

use std::fmt::{Display, Formatter, Result as FmtResult};

use hyper::{Body, Response, StatusCode};
use state::error::StateError;

use super::router::{build_500_response, build_response_from_status_code};

/// The error type for errors that occur during ApiServer execution
#[derive(Debug)]
pub enum ApiServerError {
    /// An http error code, should be forwarded as a response
    HttpStatusCode(StatusCode, String),
    /// HTTP server has failed
    HttpServerFailure(String),
    /// Error setting up the API server
    Setup(String),
    /// Error interacting with global state
    State(StateError),
    /// Websocket server has failed
    WebsocketServerFailure(String),
}

impl Display for ApiServerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{:?}", self)
    }
}

impl From<StateError> for ApiServerError {
    fn from(value: StateError) -> Self {
        ApiServerError::State(value)
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

/// Create an `ApiServerError` with a 400 bad request code
pub(crate) fn bad_request(e: String) -> ApiServerError {
    ApiServerError::HttpStatusCode(StatusCode::BAD_REQUEST, e)
}

/// Create an `ApiServerError` with a 401 unauthorized code
pub(crate) fn unauthorized(e: String) -> ApiServerError {
    ApiServerError::HttpStatusCode(StatusCode::UNAUTHORIZED, e)
}

/// Create an `ApiServerError` with a 404 not found code
pub(crate) fn not_found(e: String) -> ApiServerError {
    ApiServerError::HttpStatusCode(StatusCode::NOT_FOUND, e)
}
