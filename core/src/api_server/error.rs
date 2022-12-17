//! Defines error types that occur in the ApiServer

/// The error type for errors that occur during ApiServer execution
#[derive(Clone, Debug)]
pub enum ApiServerError {
    /// Error setting up the API server
    Setup(String),
    /// HTTP server has failed
    HttpServerFailure(String),
}
