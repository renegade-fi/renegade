//! Helpers for the authentication module

use base64::engine::{general_purpose as b64_general_purpose, Engine};
use external_api::auth::HMAC_LEN;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::types::wallet::keychain::HmacKey;
use hyper::HeaderMap;

use crate::error::{bad_request, unauthorized, ApiServerError};

/// Error displayed when a signature has expired
const ERR_EXPIRED: &str = "signature expired";

/// Check a timestamp on a signature
pub(crate) fn check_auth_timestamp(expiration_ts: u64) -> Result<(), ApiServerError> {
    let now = SystemTime::now();
    let target_duration = Duration::from_millis(expiration_ts);
    let target_time = UNIX_EPOCH + target_duration;

    if now >= target_time {
        return Err(unauthorized(ERR_EXPIRED.to_string()));
    }

    Ok(())
}

/// Compute the HMAC of a request using the given key
pub(crate) fn compute_expiring_hmac(key: &HmacKey, payload: &[u8], expiration: u64) -> Vec<u8> {
    // Check the MAC on the payload concatenated with the expiration timestamp
    let msg_bytes = [payload, &expiration.to_le_bytes()].concat();
    key.compute_mac(&msg_bytes)
}

// ---------------------------
// | Old Auth Implementation |
// ---------------------------

// TODO: Delete the old auth implementation

/// Error displayed when the signature format is invalid
const ERR_SIG_FORMAT_INVALID: &str = "signature format invalid";
/// Error displayed when the signature header is missing
const ERR_SIG_HEADER_MISSING: &str = "signature missing from headers";
/// Error displayed when the expiration format is invalid
const ERR_EXPIRATION_FORMAT_INVALID: &str = "could not parse signature expiration timestamp";
/// Error displayed when the expiration header is missing
const ERR_EXPIRATION_HEADER_MISSING: &str = "signature expiration missing from headers";
/// Error displayed when the HMAC format is invalid
const ERR_HMAC_FORMAT_INVALID: &str = "could not parse HMAC";
/// Error displayed when the HMAC header is missing
const ERR_HMAC_MISSING: &str = "HMAC missing from headers";

/// Header name for the HTTP auth signature
pub(crate) const RENEGADE_AUTH_HEADER_NAME: &str = "renegade-auth";
/// Header name for the HTTP auth expiration
pub(crate) const RENEGADE_SIG_EXPIRATION_HEADER_NAME: &str = "renegade-auth-expiration";
/// Header name for the HTTP auth HMAC
pub(crate) const RENEGADE_AUTH_HMAC_HEADER_NAME: &str = "renegade-auth-symmetric";

/// Parse an expiration timestamp from headers
///
/// TODO: Delete this once we move to the new authentication scheme
pub(crate) fn parse_sig_expiration(headers: &HeaderMap) -> Result<u64, ApiServerError> {
    let sig_expiration = headers
        .get(RENEGADE_SIG_EXPIRATION_HEADER_NAME)
        .ok_or_else(|| bad_request(ERR_EXPIRATION_HEADER_MISSING.to_string()))?;
    sig_expiration
        .to_str()
        .map_err(|_| bad_request(ERR_EXPIRATION_FORMAT_INVALID.to_string()))
        .and_then(|s| {
            s.parse::<u64>().map_err(|_| bad_request(ERR_EXPIRATION_FORMAT_INVALID.to_string()))
        })
}

/// Parse a signature from the given header
///
/// TODO: Delete this once we move to the new authentication scheme
pub(crate) fn parse_signature_from_header(headers: &HeaderMap) -> Result<Vec<u8>, ApiServerError> {
    let b64_signature: &str = headers
        .get(RENEGADE_AUTH_HEADER_NAME)
        .ok_or_else(|| bad_request(ERR_SIG_HEADER_MISSING.to_string()))?
        .to_str()
        .map_err(|_| bad_request(ERR_SIG_FORMAT_INVALID.to_string()))?;
    b64_general_purpose::STANDARD_NO_PAD
        .decode(b64_signature)
        .map_err(|_| bad_request(ERR_SIG_FORMAT_INVALID.to_string()))
}

/// Parse an HMAC from headers
pub(crate) fn parse_hmac(headers: &HeaderMap) -> Result<[u8; HMAC_LEN], ApiServerError> {
    let b64_hmac: &str = headers
        .get(RENEGADE_AUTH_HMAC_HEADER_NAME)
        .ok_or_else(|| bad_request(ERR_HMAC_MISSING.to_string()))?
        .to_str()
        .map_err(|_| bad_request(ERR_HMAC_FORMAT_INVALID.to_string()))?;

    b64_general_purpose::STANDARD_NO_PAD
        .decode(b64_hmac)
        .map_err(|_| bad_request(ERR_HMAC_FORMAT_INVALID.to_string()))?
        .try_into()
        .map_err(|_| bad_request(ERR_HMAC_FORMAT_INVALID.to_string()))
}
