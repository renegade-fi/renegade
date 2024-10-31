//! Defines authentication primitives for the API server

use common::types::wallet::{keychain::HmacKey, WalletIdentifier};
use external_api::auth::validate_expiring_auth;
use hyper::HeaderMap;
use state::State;
use tracing::warn;

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
        path: &str,
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

        // Try v2 auth first, then fall back to v1
        if Self::authenticate_wallet_request_v2(path, headers, payload, &symmetric_key).is_ok() {
            return Ok(());
        }

        authenticate_wallet_request(headers, payload, &symmetric_key)?;
        warn!("Use of v1 wallet auth will be deprecated soon");
        Ok(())
    }

    /// Authenticate a wallet request using v2 auth
    pub(crate) fn authenticate_wallet_request_v2(
        path: &str,
        headers: &HeaderMap,
        payload: &[u8],
        key: &HmacKey,
    ) -> Result<(), ApiServerError> {
        validate_expiring_auth(path, headers, payload, key)?;
        Ok(())
    }

    /// Authenticate an admin request
    pub fn authenticate_admin_request(
        &self,
        path: &str,
        headers: &HeaderMap,
        payload: &[u8],
    ) -> Result<(), ApiServerError> {
        if self.admin_key.is_none() {
            return Err(not_found(ERR_ADMIN_API_DISABLED));
        }

        // Try v2 auth first, then fall back to v1
        let admin_key = self.admin_key.as_ref().unwrap();
        if Self::authenticate_admin_request_v2(path, headers, payload, admin_key).is_ok() {
            return Ok(());
        }

        authenticate_admin_request(admin_key, headers, payload)?;
        warn!("Use of v1 admin auth will be deprecated soon");
        Ok(())
    }

    /// Authenticate an admin request using v2 auth
    pub(crate) fn authenticate_admin_request_v2(
        path: &str,
        headers: &HeaderMap,
        payload: &[u8],
        key: &HmacKey,
    ) -> Result<(), ApiServerError> {
        validate_expiring_auth(path, headers, payload, key)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use base64::{engine::general_purpose::STANDARD_NO_PAD as b64, Engine};
    use external_api::{
        auth::{add_expiring_auth_to_headers, create_request_signature},
        RENEGADE_AUTH_HEADER_NAME, RENEGADE_SIG_EXPIRATION_HEADER_NAME,
    };
    use hyper::header::HeaderValue;
    use util::get_current_time_millis;

    use super::*;

    /// Get a dummy path, header map, and payload
    fn get_dummy_path_header_map_payload() -> (&'static str, HeaderMap, &'static [u8]) {
        ("/test", HeaderMap::new(), b"test request")
    }

    /// Sign a request and add the signature and expiration to the headers
    fn sign_request_add_expiration(
        path: &str,
        headers: &mut HeaderMap,
        payload: &[u8],
        key: &HmacKey,
    ) {
        // Add an expiration timestamp to the headers
        let expiration = Duration::from_secs(1);
        add_expiring_auth_to_headers(path, headers, payload, key, expiration);
    }

    /// Sign a request and add the signature to the headers, without an
    /// expiration
    fn sign_request(path: &str, headers: &mut HeaderMap, payload: &[u8], key: &HmacKey) {
        // Create the signature and add it to the headers as a base64 encoded string
        let signature = create_request_signature(path, headers, payload, key);
        let b64_signature = b64.encode(signature);
        let sig_header = HeaderValue::from_str(&b64_signature).unwrap();
        headers.insert(RENEGADE_AUTH_HEADER_NAME, sig_header);
    }

    /// Test that v2 wallet auth works correctly
    #[test]
    #[allow(non_snake_case)]
    fn test_v2_wallet_auth__successful() {
        let key = HmacKey::random();
        let (path, mut headers, payload) = get_dummy_path_header_map_payload();

        sign_request_add_expiration(path, &mut headers, payload, &key);
        AuthMiddleware::authenticate_wallet_request_v2(path, &headers, payload, &key).unwrap();
    }

    /// Test that v2 wallet auth fails correctly when the signature is expired
    #[test]
    #[should_panic(expected = "signature expired")]
    #[allow(non_snake_case)]
    fn test_v2_wallet_auth__expired() {
        let key = HmacKey::random();
        let (path, mut headers, payload) = get_dummy_path_header_map_payload();
        let ts = get_current_time_millis() - 1000; // Expired one second ago
        headers.insert(RENEGADE_SIG_EXPIRATION_HEADER_NAME, ts.into());

        sign_request(path, &mut headers, payload, &key);
        AuthMiddleware::authenticate_wallet_request_v2(path, &headers, payload, &key).unwrap();
    }

    /// Test that v2 wallet auth fails correctly when the signature is invalid
    #[test]
    #[should_panic(expected = "invalid signature")]
    #[allow(non_snake_case)]
    fn test_v2_wallet_auth__invalid_signature() {
        let key = HmacKey::random();
        let (path, mut headers, payload) = get_dummy_path_header_map_payload();
        sign_request_add_expiration(path, &mut headers, payload, &key);

        // Add an extra header to change the mac payload
        headers.insert("x-renegade-extra-header", "extra".parse().unwrap());
        AuthMiddleware::authenticate_wallet_request_v2(path, &headers, payload, &key).unwrap();
    }

    /// Test that admin auth works correctly
    #[test]
    #[allow(non_snake_case)]
    fn test_admin_auth__successful() {
        let key = HmacKey::random();
        let (path, mut headers, payload) = get_dummy_path_header_map_payload();

        sign_request_add_expiration(path, &mut headers, payload, &key);
        AuthMiddleware::authenticate_admin_request_v2(path, &headers, payload, &key).unwrap();
    }

    /// Test that admin auth fails correctly when the signature is expired
    #[test]
    #[should_panic(expected = "signature expired")]
    #[allow(non_snake_case)]
    fn test_admin_auth__expired() {
        let key = HmacKey::random();
        let (path, mut headers, payload) = get_dummy_path_header_map_payload();
        let ts = get_current_time_millis() - 1000; // Expired one second ago
        headers.insert(RENEGADE_SIG_EXPIRATION_HEADER_NAME, ts.into());

        sign_request(path, &mut headers, payload, &key);
        AuthMiddleware::authenticate_admin_request_v2(path, &headers, payload, &key).unwrap();
    }

    /// Test that admin auth fails correctly when the signature is invalid
    #[test]
    #[should_panic(expected = "invalid signature")]
    #[allow(non_snake_case)]
    fn test_admin_auth__invalid_signature() {
        let key = HmacKey::random();
        let (path, mut headers, payload) = get_dummy_path_header_map_payload();
        sign_request_add_expiration(path, &mut headers, payload, &key);

        // Add an extra header to change the mac payload
        headers.insert("x-renegade-extra-header", "extra".parse().unwrap());
        AuthMiddleware::authenticate_admin_request_v2(path, &headers, payload, &key).unwrap();
    }
}
