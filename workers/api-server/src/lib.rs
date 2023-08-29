//! Defines the server for the publicly facing API (both HTTP and websocket)
//! that the relayer exposes

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![feature(let_chains)]
#![feature(generic_const_exprs)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use circuit_types::keychain::PublicSigningKey;
use hyper::{HeaderMap, StatusCode};
use mpc_stark::algebra::stark_curve::StarkPoint;
use renegade_crypto::ecdsa::{verify_signed_bytes, Signature};

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
fn authenticate_wallet_request(
    headers: HeaderMap,
    body: &[u8],
    pk_root: &PublicSigningKey,
) -> Result<(), ApiServerError> {
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

    // Recover a public key from the scalar serialization of its affine coordinates
    let root_key: StarkPoint = pk_root.into();
    if !validate_expiring_signature(body, expiration, signature, &root_key)? {
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
fn validate_expiring_signature(
    body: &[u8],
    expiration_timestamp: u64,
    signature: &[u8],
    pk_root: &StarkPoint,
) -> Result<bool, ApiServerError> {
    // Check the expiration timestamp
    let now = SystemTime::now();
    let target_duration = Duration::from_millis(expiration_timestamp);
    let target_time = UNIX_EPOCH + target_duration;

    if now >= target_time {
        return Ok(false);
    }

    // Concatenate the body and the expiration timestamp to check the signature against
    let message = [body, expiration_timestamp.to_le_bytes().as_ref()].concat();

    // Check the signature
    let sig: Signature = serde_json::from_slice(signature).map_err(|_| {
        ApiServerError::HttpStatusCode(StatusCode::BAD_REQUEST, ERR_SIG_FORMAT_INVALID.to_string())
    })?;

    Ok(verify_signed_bytes(&message, &sig, pk_root))
}
