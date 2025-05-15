//! Helpers for setting up a gas wallet for the relayer

use common::types::hmac::HmacKey;
use external_api::auth::add_expiring_auth_to_headers;
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, time::Duration};

use libp2p::PeerId;
use toml::Value;
use tracing::{info, warn};

use crate::helpers::read_env_var;

// -------------
// | Constants |
// -------------

/// The chain env environment variable
///
/// This is a value like `arbitrum-sepolia`
const ENV_CHAIN: &str = "CHAIN";
/// The funds manager api URL
const ENV_FUNDS_MANAGER_URL: &str = "FUNDS_MANAGER_URL";
/// The funds manager api key
const ENV_FUNDS_MANAGER_KEY: &str = "FUNDS_MANAGER_KEY";

/// The gas wallet in the relayer config
const CONFIG_GAS_WALLET: &str = "private-key";
/// The route to register a gas wallet for a peer
pub const REGISTER_GAS_WALLET_ROUTE: &str = "register-gas-wallet";

/// The signature duration on requests to the funds manager
const SIGNATURE_DURATION: Duration = Duration::from_secs(10);

// ---------------------------
// | Funds Manager API Types |
// ---------------------------

/// A request to allocate a gas wallet for a peer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterGasWalletRequest {
    /// The peer ID of the peer to allocate a gas wallet for
    pub peer_id: String,
}

/// The response containing an newly active gas wallet's key
///
/// Clients will hit the corresponding endpoint to register a gas wallet with
/// the funds manager when they spin up
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterGasWalletResponse {
    /// The key of the active gas wallet
    pub key: String,
}

// -----------------------
// | Register Gas Wallet |
// -----------------------

/// Setup the relayer's gas wallet using the funds manager api
pub(crate) async fn setup_gas_wallet(
    peer_id: PeerId,
    config: &mut HashMap<String, Value>,
) -> Result<(), String> {
    info!("registering gas wallet for relayer...");
    let url = match read_env_var::<String>(ENV_FUNDS_MANAGER_URL) {
        Ok(url) => url,
        Err(_) => {
            warn!("funds manager url not set, skipping gas wallet registration...");
            return Ok(());
        },
    };
    let key = read_funds_manager_key()?;

    // Prepare the request
    let client = Client::new();
    let chain = read_env_var::<String>(ENV_CHAIN)?;
    let path = format!("/custody/{chain}/gas-wallets/{REGISTER_GAS_WALLET_ROUTE}");
    let body = RegisterGasWalletRequest { peer_id: peer_id.to_string() };
    let body_json = serde_json::to_vec(&body).unwrap();

    // Prepare headers
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    add_expiring_auth_to_headers(&path, &mut headers, &body_json, &key, SIGNATURE_DURATION);

    // Send request
    let url = format!("{}{}", url, path);
    let response = client
        .post(&url)
        .headers(headers)
        .body(body_json)
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("Request failed with status: {}", response.status()));
    }

    let resp = response
        .json::<RegisterGasWalletResponse>()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    let key = Value::String(resp.key);
    config.insert(CONFIG_GAS_WALLET.to_string(), Value::Array(vec![key]));

    Ok(())
}

/// Read in the funds manager HMAC key from environment variables
fn read_funds_manager_key() -> Result<HmacKey, String> {
    let key_str = read_env_var::<String>(ENV_FUNDS_MANAGER_KEY)?;
    HmacKey::from_hex_string(&key_str).map_err(|e| format!("Invalid HMAC key: {}", e))
}
