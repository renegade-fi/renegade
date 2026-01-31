//! HTTP client for the darkpool indexer API

use std::time::Duration;

use external_api::auth::add_expiring_auth_to_headers;
use http::HeaderMap;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use types_account::order::Order;
use types_core::{AccountId, HmacKey};
use url::Url;

// -------------
// | Constants |
// -------------

/// The path for the get user state endpoint
const GET_USER_STATE_PATH: &str = "/user-state";
/// The expiration duration for auth signatures
const AUTH_EXPIRATION: Duration = Duration::from_secs(30);

// ----------
// | Errors |
// ----------

/// Error type for the indexer client
#[derive(Debug, Error)]
pub enum IndexerClientError {
    /// Error building the request URL
    #[error("error building request URL: {0}")]
    UrlBuild(String),
    /// Error sending HTTP request
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    /// Serialization/deserialization error
    #[error("serde error: {0}")]
    Serde(String),
    /// Non-success status code
    #[error("request failed with status {0}: {1}")]
    StatusCode(u16, String),
}

impl IndexerClientError {
    /// Create a new URL build error
    #[allow(clippy::needless_pass_by_value)]
    pub fn url_build<T: ToString>(msg: T) -> Self {
        Self::UrlBuild(msg.to_string())
    }

    /// Create a new serde error
    #[allow(clippy::needless_pass_by_value)]
    pub fn serde<T: ToString>(msg: T) -> Self {
        Self::Serde(msg.to_string())
    }
}

// -----------------------
// | Duplicated API Types |
// -----------------------

/// A state object returned by the indexer API
#[derive(Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum ApiStateObject {
    /// A balance state object
    Balance(ApiBalance),
    /// An intent state object
    Intent(ApiIntent),
    /// A public intent state object
    PublicIntent(ApiPublicIntent),
}

/// A balance state object returned by the API
#[derive(Serialize, Deserialize)]
pub struct ApiBalance {
    // Note: We don't need to fully deserialize this for now
    // as we only care about public intents
}

/// An intent state object returned by the API
#[derive(Serialize, Deserialize)]
pub struct ApiIntent {
    // Note: We don't need to fully deserialize this for now
    // as we only care about public intents
}

/// A public intent state object returned by the API
#[derive(Serialize, Deserialize)]
pub struct ApiPublicIntent {
    /// The underlying order type
    pub order: Order,
    /// The matching pool to which the intent is allocated
    pub matching_pool: String,
}

/// A response containing a user's active state objects
#[derive(Serialize, Deserialize)]
pub struct GetUserStateResponse {
    /// The list of active state objects
    pub active_state_objects: Vec<ApiStateObject>,
}

// -----------------
// | IndexerClient |
// -----------------

/// HTTP client for the darkpool indexer API
#[derive(Clone)]
pub struct IndexerClient {
    /// The underlying HTTP client
    client: Client,
    /// The base URL of the indexer API
    base_url: Url,
    /// The HMAC key for request authentication
    hmac_key: HmacKey,
}

impl IndexerClient {
    /// Create a new indexer client
    pub fn new(base_url: Url, hmac_key: HmacKey) -> Self {
        let client = Client::new();
        Self { client, base_url, hmac_key }
    }

    /// Get the user state for an account
    pub async fn get_user_state(
        &self,
        account_id: AccountId,
    ) -> Result<GetUserStateResponse, IndexerClientError> {
        // Build the request URL
        let path = format!("{}/{}", GET_USER_STATE_PATH, account_id);
        let url = self.base_url.join(&path).map_err(IndexerClientError::url_build)?;

        // Build and sign the request headers
        let mut headers = HeaderMap::new();
        add_expiring_auth_to_headers(&path, &mut headers, &[], &self.hmac_key, AUTH_EXPIRATION);

        // Send the request
        let response = self.client.get(url).headers(headers).send().await?;

        // Check for errors
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(IndexerClientError::StatusCode(status.as_u16(), body));
        }

        // Deserialize the response
        let body = response.text().await?;
        serde_json::from_str(&body).map_err(IndexerClientError::serde)
    }
}
