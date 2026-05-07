//! HTTP route definitions and request/response types for account operations

use alloy::primitives::Address;
use circuit_types::schnorr::SchnorrPublicKey;
use constants::Scalar;
use serde::{Deserialize, Serialize};
use types_core::HmacKey;
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
    #[serde(with = "serde_helpers::hmac_key_as_base64_string")]
    pub auth_hmac_key: HmacKey,
    /// The schnorr public key used for in-circuit verification
    #[serde(with = "serde_helpers::schnorr_public_key_as_string")]
    pub schnorr_public_key: SchnorrPublicKey,
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
    #[serde(with = "serde_helpers::hmac_key_as_base64_string")]
    pub auth_hmac_key: HmacKey,
    /// The schnorr public key used for in-circuit verification
    #[serde(with = "serde_helpers::schnorr_public_key_as_string")]
    pub schnorr_public_key: SchnorrPublicKey,
    /// Tokens whose Ring 0 backing balances should be re-fetched from
    /// chain in addition to those that appear in the wallet's active
    /// public intents. Useful for callers that need to force a balance
    /// refresh for a token before placing the first order against it
    /// (otherwise the relayer's per-token balance index can be stale,
    /// since `refresh_state` only walks tokens referenced by current
    /// intents). Defaults to empty for backward compatibility.
    #[serde(default)]
    pub additional_tokens: Vec<Address>,
}

/// Response from syncing an account
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncAccountResponse {
    /// The task identifier for the sync operation
    pub task_id: Uuid,
    /// Whether the sync has already completed
    pub completed: bool,
}
