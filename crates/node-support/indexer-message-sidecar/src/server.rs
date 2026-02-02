//! Warp HTTP server implementation

use std::sync::Arc;

use aws_sdk_sqs::Client as SqsClient;
use eyre::Result;
use reqwest::Client as HttpClient;
use task_driver::utils::indexer_client::{GET_USER_STATE_PATH, Message, SUBMIT_MESSAGE_PATH};
use thiserror::Error;
use tracing::{error, info};
use url::Url;
use warp::{Filter, Rejection, Reply, http::StatusCode, reject::Reject};

use crate::sqs::submit_message;

// ----------
// | Errors |
// ----------

/// Error type for the HTTP server
#[derive(Debug, Error)]
enum ServerError {
    /// Error proxying a request to the indexer
    #[error("proxy error: {0}")]
    Proxy(String),
    /// Error sending a message to SQS
    #[error("SQS error: {0}")]
    Sqs(String),
    /// Error deserializing a request body
    #[error("deserialization error: {0}")]
    #[allow(dead_code)]
    Deserialize(String),
}

impl ServerError {
    /// Create a new proxy error
    #[allow(clippy::needless_pass_by_value)]
    pub fn proxy<T: ToString>(msg: T) -> Self {
        Self::Proxy(msg.to_string())
    }

    /// Create a new SQS error
    #[allow(clippy::needless_pass_by_value)]
    pub fn sqs<T: ToString>(msg: T) -> Self {
        Self::Sqs(msg.to_string())
    }

    /// Create a new deserialization error
    #[allow(dead_code, clippy::needless_pass_by_value)]
    pub fn deserialize<T: ToString>(msg: T) -> Self {
        Self::Deserialize(msg.to_string())
    }
}

impl Reject for ServerError {}

// ----------------
// | Server State |
// ----------------

/// Shared state for the server handlers
struct ServerState {
    /// HTTP client for proxying requests
    http_client: HttpClient,
    /// The URL of the real indexer
    indexer_url: Url,
    /// SQS client for sending messages
    sqs_client: SqsClient,
    /// The SQS queue URL
    queue_url: String,
}

// ----------
// | Server |
// ----------

/// Run the HTTP server
pub async fn run_server(
    port: u16,
    indexer_url: Url,
    sqs_client: SqsClient,
    queue_url: String,
) -> Result<()> {
    let state = Arc::new(ServerState {
        http_client: HttpClient::new(),
        indexer_url,
        sqs_client,
        queue_url,
    });

    // Build routes
    let user_state_route = build_user_state_route(state.clone());
    let submit_message_route = build_submit_message_route(state);

    let routes = user_state_route.or(submit_message_route).recover(handle_rejection);

    info!("Starting server on port {port}");
    warp::serve(routes).run(([127, 0, 0, 1], port)).await;

    Ok(())
}

// ----------
// | Routes |
// ----------

/// Build the user state proxy route
fn build_user_state_route(
    state: Arc<ServerState>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path(GET_USER_STATE_PATH)
        .and(warp::path::param::<String>())
        .and(warp::get())
        .and(warp::header::headers_cloned())
        .and(with_state(state))
        .and_then(handle_user_state)
}

/// Build the submit message route
fn build_submit_message_route(
    state: Arc<ServerState>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path(SUBMIT_MESSAGE_PATH)
        .and(warp::post())
        .and(warp::body::json())
        .and(with_state(state))
        .and_then(handle_submit_message)
}

/// Helper filter to inject state
fn with_state(
    state: Arc<ServerState>,
) -> impl Filter<Extract = (Arc<ServerState>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || state.clone())
}

// ------------
// | Handlers |
// ------------

/// Handle user state proxy requests
async fn handle_user_state(
    account_id: String,
    headers: warp::http::HeaderMap,
    state: Arc<ServerState>,
) -> Result<impl Reply, Rejection> {
    // Build the target URL
    let path = format!("/{GET_USER_STATE_PATH}/{account_id}");
    let target_url =
        state.indexer_url.join(&path).map_err(|e| warp::reject::custom(ServerError::proxy(e)))?;

    // Convert warp headers to reqwest headers
    let mut reqwest_headers = reqwest::header::HeaderMap::new();
    for (key, value) in headers.iter() {
        let name = reqwest::header::HeaderName::from_bytes(key.as_str().as_bytes());
        let val = reqwest::header::HeaderValue::from_bytes(value.as_bytes());
        if let (Ok(name), Ok(val)) = (name, val) {
            reqwest_headers.insert(name, val);
        }
    }

    // Make the proxied request
    let response = state
        .http_client
        .get(target_url)
        .headers(reqwest_headers)
        .send()
        .await
        .map_err(|e| warp::reject::custom(ServerError::proxy(e)))?;

    // Get the status and body
    let status = response.status();
    let body = response.bytes().await.map_err(|e| warp::reject::custom(ServerError::proxy(e)))?;

    // Build the response with the same status code
    let warp_status =
        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    Ok(warp::reply::with_status(body.to_vec(), warp_status))
}

/// Handle submit message requests
async fn handle_submit_message(
    message: Message,
    state: Arc<ServerState>,
) -> Result<impl Reply, Rejection> {
    submit_message(&state.sqs_client, &state.queue_url, message)
        .await
        .map_err(|e| warp::reject::custom(ServerError::sqs(e)))?;

    Ok(warp::reply::with_status("Message submitted", StatusCode::OK))
}

// ---------------------
// | Error Handling    |
// ---------------------

/// Handle rejections and convert them to HTTP responses
async fn handle_rejection(err: Rejection) -> Result<impl Reply, std::convert::Infallible> {
    let (code, message) = if let Some(e) = err.find::<ServerError>() {
        error!("{e}");
        match e {
            ServerError::Proxy(_) => (StatusCode::BAD_GATEWAY, e.to_string()),
            ServerError::Sqs(_) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            ServerError::Deserialize(_) => (StatusCode::BAD_REQUEST, e.to_string()),
        }
    } else if err.is_not_found() {
        (StatusCode::NOT_FOUND, "Not found".to_string())
    } else if err.find::<warp::reject::MethodNotAllowed>().is_some() {
        (StatusCode::METHOD_NOT_ALLOWED, "Method not allowed".to_string())
    } else {
        error!("Unhandled rejection: {:?}", err);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
    };

    Ok(warp::reply::with_status(message, code))
}
