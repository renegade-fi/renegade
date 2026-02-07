//! HTTP client for the darkpool indexer API

use std::time::Duration;

use alloy::primitives::{Address, B256};
use circuit_types::Amount;
use constants::Scalar;
use darkpool_types::intent::Intent;
use external_api::{auth::add_expiring_auth_to_headers, types::SignatureWithNonce};
use http::{HeaderMap, HeaderValue, header::CONTENT_TYPE};
use renegade_solidity_abi::v2::IDarkpoolV2::PublicIntentPermit;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;
use types_account::order::Order;
use types_core::{AccountId, HmacKey};
use url::Url;
use uuid::Uuid;

// -------------
// | Constants |
// -------------

/// The path for the get user state endpoint (without leading slash)
pub const GET_USER_STATE_PATH: &str = "user-state";
/// The path for the submit message endpoint (without leading slash)
pub const SUBMIT_MESSAGE_PATH: &str = "submit-message";
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
    /// The permit for the intent
    pub permit: PublicIntentPermit,
    /// The intent signature
    pub intent_signature: SignatureWithNonce,
    /// The matching pool to which the intent is allocated
    pub matching_pool: String,
}

/// A response containing a user's active state objects
#[derive(Serialize, Deserialize)]
pub struct GetUserStateResponse {
    /// The list of active state objects
    pub active_state_objects: Vec<ApiStateObject>,
}

// ---------------------------
// | Duplicated Message Types |
// ---------------------------

/// The message types that can be submitted to the indexer via the sidecar
#[derive(Serialize, Deserialize, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Message {
    /// A message representing the registration of a new master view seed
    RegisterMasterViewSeed(MasterViewSeedMessage),
    /// A message representing an update to a public intent's metadata
    UpdatePublicIntentMetadata(PublicIntentMetadataUpdateMessage),
}

/// A message representing the registration of a new master view seed
#[derive(Serialize, Deserialize, Clone)]
pub struct MasterViewSeedMessage {
    /// The account ID of the seed owner
    pub account_id: Uuid,
    /// The address of the seed's owner
    pub owner_address: Address,
    /// The master view seed
    pub seed: Scalar,
}

/// A message representing an update to a public intent's metadata
#[derive(Serialize, Deserialize, Clone)]
pub struct PublicIntentMetadataUpdateMessage {
    /// The intent hash
    pub intent_hash: B256,
    /// The public intent
    pub intent: Intent,
    /// The intent signature
    pub intent_signature: SignatureWithNonce,
    /// The permit for the intent
    pub permit: PublicIntentPermit,
    /// The order ID
    pub order_id: Uuid,
    /// The matching pool to which the intent is allocated
    pub matching_pool: String,
    /// Whether the intent allows external matches
    pub allow_external_matches: bool,
    /// The minimum fill size allowed for the intent
    pub min_fill_size: Amount,
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
        let path = format!("/{GET_USER_STATE_PATH}/{account_id}");
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

    /// Submit a message to the indexer via the sidecar
    ///
    /// This endpoint is unauthenticated as the sidecar runs locally.
    pub async fn submit_message(&self, message: Message) -> Result<(), IndexerClientError> {
        // Build the request URL
        let path = format!("/{SUBMIT_MESSAGE_PATH}");
        let url = self.base_url.join(&path).map_err(IndexerClientError::url_build)?;

        // Serialize the message
        let body = serde_json::to_vec(&message).map_err(IndexerClientError::serde)?;

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        add_expiring_auth_to_headers(&path, &mut headers, &body, &self.hmac_key, AUTH_EXPIRATION);

        // Send the request (no auth required for local sidecar)
        let response = self.client.post(url).headers(headers).body(body).send().await?;

        // Check for errors
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(IndexerClientError::StatusCode(status.as_u16(), body));
        }

        Ok(())
    }
}
