//! Defines error types that occur in the ApiServer

use std::fmt::{Display, Formatter, Result as FmtResult};

use darkpool_client::errors::DarkpoolClientError;
use external_api::auth::AuthError;
use hyper::{Response, StatusCode};
use state::error::StateError;

use super::router::{ResponseBody, build_500_response, build_response_from_status_code};

/// The error message for rate limit exceeded errors
const ERR_RATE_LIMIT_EXCEEDED: &str = "Rate limit exceeded";

/// The error type for errors that occur during ApiServer execution
#[derive(Debug)]
pub enum ApiServerError {
    /// An error interacting with the compliance service
    ComplianceService(String),
    /// An http error code, should be forwarded as a response
    HttpStatusCode(StatusCode, String),
    /// An error interacting with the rate limiter
    RateLimitExceeded,
    /// HTTP server has failed
    HttpServerFailure(String),
    /// Error setting up the API server
    Setup(String),
    /// Error interacting with global state
    State(StateError),
    /// Websocket server has failed
    WebsocketServerFailure(String),
}

impl ApiServerError {
    /// An error with the server's main loop
    #[allow(clippy::needless_pass_by_value)]
    pub fn server_failure<T: ToString>(e: T) -> Self {
        ApiServerError::HttpServerFailure(e.to_string())
    }
}

impl Display for ApiServerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{:?}", self)
    }
}

impl From<hyper::Error> for ApiServerError {
    fn from(value: hyper::Error) -> Self {
        ApiServerError::server_failure(value)
    }
}

impl From<StateError> for ApiServerError {
    fn from(value: StateError) -> Self {
        ApiServerError::State(value)
    }
}

impl From<DarkpoolClientError> for ApiServerError {
    fn from(value: DarkpoolClientError) -> Self {
        internal_error(value)
    }
}

impl From<ApiServerError> for Response<ResponseBody> {
    fn from(err: ApiServerError) -> Self {
        match err {
            ApiServerError::HttpStatusCode(status, message) => {
                build_response_from_status_code(status, message)
            },
            ApiServerError::RateLimitExceeded => build_response_from_status_code(
                StatusCode::TOO_MANY_REQUESTS,
                ERR_RATE_LIMIT_EXCEEDED.to_string(),
            ),
            _ => build_500_response(err.to_string()),
        }
    }
}

impl From<AuthError> for ApiServerError {
    fn from(value: AuthError) -> Self {
        ApiServerError::HttpStatusCode(StatusCode::UNAUTHORIZED, value.to_string())
    }
}

/// Create an `ApiServerError` with a 204 no content code
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn no_content<E: ToString>(e: E) -> ApiServerError {
    ApiServerError::HttpStatusCode(StatusCode::NO_CONTENT, e.to_string())
}

/// Create an `ApiServerError` with a 400 bad request code
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn bad_request<E: ToString>(e: E) -> ApiServerError {
    ApiServerError::HttpStatusCode(StatusCode::BAD_REQUEST, e.to_string())
}

/// Create an `ApiServerError` with a 404 not found code
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn not_found<E: ToString>(e: E) -> ApiServerError {
    ApiServerError::HttpStatusCode(StatusCode::NOT_FOUND, e.to_string())
}

/// Create an `ApiServerError` with a 500 internal server error code
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn internal_error<E: ToString>(e: E) -> ApiServerError {
    ApiServerError::HttpStatusCode(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}
