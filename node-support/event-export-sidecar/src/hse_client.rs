//! A client for the historical state engine

use std::time::Duration;

use common::types::wallet::keychain::HmacKey;
use external_api::auth::add_expiring_auth_to_headers;
use eyre::{eyre, Error};
use reqwest::{header::HeaderMap, Client, Method, Response};

// -------------
// | Constants |
// -------------

/// The buffer to add to the expiration timestamp for the signature
const SIG_EXPIRATION_BUFFER_MS: u64 = 5_000; // 5 seconds

/// The path to submit events to
const EVENT_SUBMISSION_PATH: &str = "/event";

// ----------
// | Client |
// ----------

/// A client for the historical state engine
pub struct HistoricalStateClient {
    /// The base URL of the historical state engine
    base_url: String,
    /// The auth key for the historical state engine
    auth_key: HmacKey,
}

impl HistoricalStateClient {
    /// Create a new historical state engine client
    pub fn new(base_url: String, auth_key: HmacKey) -> Self {
        Self { base_url, auth_key }
    }

    /// Submit an event to the historical state engine
    pub async fn submit_event(&self, event: Vec<u8>) -> Result<(), Error> {
        send_authenticated_request(
            &self.base_url,
            EVENT_SUBMISSION_PATH,
            Method::POST,
            event,
            &self.auth_key,
        )
        .await
        .map(|_| ())
    }
}

// -----------
// | Helpers |
// -----------

/// Send a request w/ an expiring auth header
async fn send_authenticated_request(
    url: &str,
    path: &str,
    method: Method,
    body: Vec<u8>,
    key: &HmacKey,
) -> Result<Response, Error> {
    let expiration = Duration::from_millis(SIG_EXPIRATION_BUFFER_MS);

    let mut headers = HeaderMap::new();
    add_expiring_auth_to_headers(path, &mut headers, &body, key, expiration);

    let route = format!("{}{}", url, path);
    let response = send_request(&route, method, body, headers).await?;
    Ok(response)
}

/// Send a basic HTTP request
async fn send_request(
    route: &str,
    method: Method,
    body: Vec<u8>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let response = Client::new()
        .request(method, route)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|e| eyre!("Failed to send request: {e}"))?;

    // Check if the request was successful
    if !response.status().is_success() {
        return Err(eyre!("Request failed with status: {}", response.status()));
    }

    Ok(response)
}
