//! Auth helpers for the external API

use base64::engine::{general_purpose as b64_general_purpose, Engine};
use common::types::hmac::HmacKey;
use http::{HeaderMap, HeaderValue};
use itertools::Itertools;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use util::get_current_time_millis;

use crate::{RENEGADE_AUTH_HEADER_NAME, RENEGADE_SIG_EXPIRATION_HEADER_NAME};

use super::{AuthError, HMAC_LEN};

/// The header namespace to include in the HMAC
const RENEGADE_HEADER_NAMESPACE: &str = "x-renegade";

// --------------------
// | Public Interface |
// --------------------

/// Validate a request signature with an expiration
pub fn validate_expiring_auth(
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
    key: &HmacKey,
) -> Result<(), AuthError> {
    // First check the expiration
    let expiration_ts = parse_auth_expiration_from_headers(headers)?;
    check_auth_timestamp(expiration_ts)?;

    // Then check the signature
    validate_auth(path, headers, body, key)
}

/// Validate a request signature without an expiration
pub fn validate_auth(
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
    key: &HmacKey,
) -> Result<(), AuthError> {
    // Parse the MAC from headers
    let mac = parse_hmac_from_headers(headers)?;

    // Compute the expected HMAC
    let expected_mac = create_request_signature(path, headers, body, key);
    if expected_mac != mac {
        return Err(AuthError::InvalidSignature);
    }

    Ok(())
}

/// Add an auth expiration and signature to a set of headers
pub fn add_expiring_auth_to_headers(
    path: &str,
    headers: &mut HeaderMap,
    body: &[u8],
    key: &HmacKey,
    expiration: Duration,
) {
    // Add a timestamp
    let expiration_ts = get_current_time_millis() + expiration.as_millis() as u64;
    headers.insert(RENEGADE_SIG_EXPIRATION_HEADER_NAME, expiration_ts.into());

    // Add the signature
    let sig = create_request_signature(path, headers, body, key);
    let b64_sig = b64_general_purpose::STANDARD_NO_PAD.encode(sig);
    let sig_header = HeaderValue::from_str(&b64_sig).expect("b64 encoding should not fail");
    headers.insert(RENEGADE_AUTH_HEADER_NAME, sig_header);
}

/// Create a request signature
pub fn create_request_signature(
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
    key: &HmacKey,
) -> Vec<u8> {
    // Compute the expected HMAC
    let path_bytes = path.as_bytes();
    let header_bytes = get_header_bytes(headers);
    let payload = [path_bytes, &header_bytes, body].concat();

    key.compute_mac(&payload)
}

/// Parse an HMAC from headers
pub fn parse_hmac_from_headers(headers: &HeaderMap) -> Result<[u8; HMAC_LEN], AuthError> {
    let b64_hmac: &str = headers
        .get(RENEGADE_AUTH_HEADER_NAME)
        .ok_or(AuthError::HmacMissing)?
        .to_str()
        .map_err(|_| AuthError::HmacFormatInvalid)?;
    b64_general_purpose::STANDARD_NO_PAD
        .decode(b64_hmac)
        .map_err(|_| AuthError::HmacFormatInvalid)?
        .try_into()
        .map_err(|_| AuthError::HmacFormatInvalid)
}

// -----------
// | Helpers |
// -----------

/// Parse an expiration timestamp from headers
fn parse_auth_expiration_from_headers(headers: &HeaderMap) -> Result<u64, AuthError> {
    let sig_expiration = headers
        .get(RENEGADE_SIG_EXPIRATION_HEADER_NAME)
        .ok_or(AuthError::SignatureExpirationMissing)?;
    sig_expiration
        .to_str()
        .map_err(|_| AuthError::ExpirationFormatInvalid)
        .and_then(|s| s.parse::<u64>().map_err(|_| AuthError::ExpirationFormatInvalid))
}

/// Check a timestamp on a signature
fn check_auth_timestamp(expiration_ts: u64) -> Result<(), AuthError> {
    let now = SystemTime::now();
    let target_duration = Duration::from_millis(expiration_ts);
    let target_time = UNIX_EPOCH + target_duration;

    if now >= target_time {
        return Err(AuthError::SignatureExpired);
    }

    Ok(())
}

/// Get the header bytes to validate in an HMAC
fn get_header_bytes(headers: &HeaderMap) -> Vec<u8> {
    let mut headers_buf = Vec::new();

    // Filter out non-Renegade headers and the auth header
    let mut renegade_headers = headers
        .iter()
        .filter_map(|(k, v)| {
            let key = k.to_string().to_lowercase();
            if key.starts_with(RENEGADE_HEADER_NAMESPACE) && key != RENEGADE_AUTH_HEADER_NAME {
                Some((key, v))
            } else {
                None
            }
        })
        .collect_vec();

    // Sort alphabetically, then add to the buffer
    renegade_headers.sort_by(|a, b| a.0.cmp(&b.0));
    for (key, value) in renegade_headers {
        headers_buf.extend_from_slice(key.as_bytes());
        headers_buf.extend_from_slice(value.as_bytes());
    }

    headers_buf
}
