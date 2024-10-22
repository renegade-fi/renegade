//! Defines authentication primitives for the API server

use common::types::wallet::{keychain::HmacKey, WalletIdentifier};
use hyper::HeaderMap;
use state::State;

use crate::{
    error::{not_found, ApiServerError},
    router::ERR_WALLET_NOT_FOUND,
};

use self::{admin_auth::authenticate_admin_request, wallet_auth::authenticate_wallet_request};

mod admin_auth;
mod helpers;
mod wallet_auth;

/// Error message emitted when the admin API is disabled
const ERR_ADMIN_API_DISABLED: &str = "Admin API is disabled";

/// Represents the auth type required for a request
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AuthType {
    /// A wallet request
    Wallet,
    /// An admin request
    Admin,
    /// No authentication is required
    None,
}

/// The authentication middleware for the API server
#[derive(Clone)]
pub struct AuthMiddleware {
    /// The admin auth key, if enabled
    admin_key: Option<HmacKey>,
    /// A handle on the relayer-global state
    state: State,
}

impl AuthMiddleware {
    /// Create a new authentication middleware
    pub fn new(admin_key: Option<HmacKey>, state: State) -> Self {
        Self { admin_key, state }
    }

    /// Whether or not admin auth is enabled
    pub fn admin_auth_enabled(&self) -> bool {
        self.admin_key.is_some()
    }

    /// Authenticate a wallet request
    pub async fn authenticate_wallet_request(
        &self,
        wallet_id: WalletIdentifier,
        headers: &HeaderMap,
        payload: &[u8],
    ) -> Result<(), ApiServerError> {
        // Look up the verification key in the global state
        let wallet = self
            .state
            .get_wallet(&wallet_id)
            .await?
            .ok_or_else(|| not_found(ERR_WALLET_NOT_FOUND.to_string()))?;
        let symmetric_key = wallet.key_chain.symmetric_key();

        authenticate_wallet_request(headers, payload, &symmetric_key)
    }

    /// Authenticate an admin request
    pub fn authenticate_admin_request(
        &self,
        headers: &HeaderMap,
        payload: &[u8],
    ) -> Result<(), ApiServerError> {
        if self.admin_key.is_none() {
            return Err(not_found(ERR_ADMIN_API_DISABLED));
        }

        authenticate_admin_request(&self.admin_key.unwrap(), headers, payload)
    }
}
