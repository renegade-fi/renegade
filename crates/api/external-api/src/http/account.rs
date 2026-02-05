//! HTTP route definitions and request/response types for account operations

use alloy::primitives::Address;
use constants::Scalar;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    serde_helpers,
    types::{ApiAccount, ApiPoseidonCSPRNG},
};

// ---------------
// | HTTP Routes |
// ---------------

/// Route to create a new account
pub const CREATE_ACCOUNT_ROUTE: &str = "/v2/account";
/// Route to get an account by ID
pub const GET_ACCOUNT_BY_ID_ROUTE: &str = "/v2/account/:account_id";
/// Route to get account seeds
pub const GET_ACCOUNT_SEEDS_ROUTE: &str = "/v2/account/:account_id/seeds";
/// Route to sync an account
pub const SYNC_ACCOUNT_ROUTE: &str = "/v2/account/:account_id/sync";

// --------------------
// | Request/Response |
// --------------------

/// Response for getting an account
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetAccountResponse {
    /// The account
    pub account: ApiAccount,
}

/// Request to create a new account
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateAccountRequest {
    /// The account identifier
    pub account_id: Uuid,
    /// The Ethereum address associated with the account
    #[serde(with = "serde_helpers::address_as_string")]
    pub address: Address,
    /// The master view seed for deriving keys
    #[serde(with = "serde_helpers::scalar_as_string")]
    pub master_view_seed: Scalar,
    /// The HMAC key for authenticating requests
    #[serde(with = "serde_helpers::bytes_as_base64_string")]
    pub auth_hmac_key: Vec<u8>,
}

/// Response for get account seeds
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetAccountSeedsResponse {
    /// The recovery seed CSPRNG state
    pub recovery_seed_csprng: ApiPoseidonCSPRNG,
    /// The share seed CSPRNG state
    pub share_seed_csprng: ApiPoseidonCSPRNG,
}

/// Request to sync an account
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncAccountRequest {
    /// The account identifier
    pub account_id: Uuid,
    /// The master view seed for deriving keys
    #[serde(with = "serde_helpers::scalar_as_hex_string")]
    pub master_view_seed: Scalar,
    /// The HMAC key for authenticating requests
    #[serde(with = "serde_helpers::bytes_as_base64_string")]
    pub auth_hmac_key: Vec<u8>,
}

/// Response from syncing an account
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncAccountResponse {
    /// The task identifier for the sync operation
    pub task_id: Uuid,
    /// Whether the sync has already completed
    pub completed: bool,
}
