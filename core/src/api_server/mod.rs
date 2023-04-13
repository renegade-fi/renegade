//! Defines the server for the publicly facing API (both HTTP and websocket)
//! that the relayer exposes

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use circuits::types::keychain::PublicSigningKey;
use ed25519_dalek::{Digest, PublicKey, Sha512, Signature};
use hyper::{HeaderMap, StatusCode};
use serde::Serialize;
use tracing::log;

use self::error::ApiServerError;
pub mod error;
mod http;
mod router;
mod websocket;
pub mod worker;

/// Header name for the HTTP auth signature
const RENEGADE_AUTH_HEADER_NAME: &str = "renegade-auth";
/// Header name for the expiration timestamp of a signature
const RENEGADE_SIG_EXPIRATION_HEADER_NAME: &str = "renegade-auth-expiration";

/// Error displayed when the signature format is invalid
const ERR_SIG_FORMAT_INVALID: &str = "signature format invalid";
/// Error displayed when the signature header is missing
const ERR_SIG_HEADER_MISSING: &str = "signature missing from request";
/// Error displayed when the signature expiration header is missing
const ERR_SIG_EXPIRATION_MISSING: &str = "signature expiration missing from headers";
/// Error displayed when the expiration format is invalid
const ERR_EXPIRATION_FORMAT_INVALID: &str = "could not parse signature expiration timestamp";
/// Error displayed when signature verification fails on a request
const ERR_SIG_VERIFICATION_FAILED: &str = "signature verification failed";

/// A helper to authenticate a request via expiring signatures using the method below
pub(self) fn authenticate_request_from_headers<T>(
    headers: HeaderMap,
    body: &T,
    pk_root: &PublicSigningKey,
) -> Result<(), ApiServerError>
where
    T: Serialize,
{
    // Parse the signature and the expiration timestamp from the header
    let signature = headers
        .get(RENEGADE_AUTH_HEADER_NAME)
        .ok_or_else(|| {
            ApiServerError::HttpStatusCode(
                StatusCode::BAD_REQUEST,
                ERR_SIG_HEADER_MISSING.to_string(),
            )
        })?
        .as_bytes();
    let sig_expiration = headers
        .get(RENEGADE_SIG_EXPIRATION_HEADER_NAME)
        .ok_or_else(|| {
            ApiServerError::HttpStatusCode(
                StatusCode::BAD_REQUEST,
                ERR_SIG_EXPIRATION_MISSING.to_string(),
            )
        })?;

    // Parse the expiration into a timestamp
    let expiration = sig_expiration
        .to_str()
        .map_err(|_| {
            ApiServerError::HttpStatusCode(
                StatusCode::BAD_REQUEST,
                ERR_EXPIRATION_FORMAT_INVALID.to_string(),
            )
        })
        .and_then(|s| {
            s.parse::<u64>().map_err(|_| {
                ApiServerError::HttpStatusCode(
                    StatusCode::BAD_REQUEST,
                    ERR_EXPIRATION_FORMAT_INVALID.to_string(),
                )
            })
        })?;

    // Recover a public key from the byte packed scalar representing the public key
    let root_key: PublicKey = pk_root.into();
    if !validate_expiring_signature(body, expiration, signature, root_key)? {
        Err(ApiServerError::HttpStatusCode(
            StatusCode::UNAUTHORIZED,
            ERR_SIG_VERIFICATION_FAILED.to_string(),
        ))
    } else {
        Ok(())
    }
}

/// A helper to verify a signature on a request body
///
/// The signature should be a sponge hash of the serialized request body
/// and a unix timestamp representing the expiration of the signature. A
/// call to this method after the expiration timestamp should return false
pub(self) fn validate_expiring_signature<T>(
    body: &T,
    expiration_timestamp: u64,
    signature: &[u8],
    pk_root: PublicKey,
) -> Result<bool, ApiServerError>
where
    T: Serialize,
{
    // Check the expiration timestamp
    let now = SystemTime::now();
    let target_duration = Duration::from_millis(expiration_timestamp);
    let target_time = UNIX_EPOCH + target_duration;

    if now >= target_time {
        return Ok(false);
    }

    // Hash the body and the expiration timestamp into a digest to check the signature against
    let mut hasher = Sha512::default();
    let body_bytes = serde_json::to_vec(&body).unwrap();
    log::info!("body bytes: {body_bytes:?}");
    hasher.update(&body_bytes);
    hasher.update(expiration_timestamp.to_le_bytes());

    let out = hasher.finalize();
    log::info!("out: {out:?}");

    let mut hasher = Sha512::default();
    let body_bytes = serde_json::to_vec(&body).unwrap();
    hasher.update(&body_bytes);
    hasher.update(expiration_timestamp.to_le_bytes());

    // Check the signature
    let sig: Signature = serde_json::from_slice(signature).map_err(|_| {
        ApiServerError::HttpStatusCode(StatusCode::BAD_REQUEST, ERR_SIG_FORMAT_INVALID.to_string())
    })?;

    Ok(pk_root
        .verify_prehashed(hasher, None /* context */, &sig)
        .is_ok())
}
