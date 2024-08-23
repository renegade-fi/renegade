//! Helpers for the authentication module

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::types::wallet::keychain::HmacKey;
use external_api::RENEGADE_SIG_EXPIRATION_HEADER_NAME;
use hyper::HeaderMap;

use crate::error::{bad_request, unauthorized, ApiServerError};

/// Error displayed when the signature expiration header is missing
const ERR_SIG_EXPIRATION_MISSING: &str = "signature expiration missing from headers";
/// Error displayed when the expiration format is invalid
const ERR_EXPIRATION_FORMAT_INVALID: &str = "could not parse signature expiration timestamp";
/// Error displayed when a signature has expired
const ERR_EXPIRED: &str = "signature expired";

/// Parse an expiration timestamp from headers
pub(crate) fn parse_sig_expiration(headers: &HeaderMap) -> Result<u64, ApiServerError> {
    let sig_expiration = headers
        .get(RENEGADE_SIG_EXPIRATION_HEADER_NAME)
        .ok_or_else(|| bad_request(ERR_SIG_EXPIRATION_MISSING.to_string()))?;
    sig_expiration
        .to_str()
        .map_err(|_| bad_request(ERR_EXPIRATION_FORMAT_INVALID.to_string()))
        .and_then(|s| {
            s.parse::<u64>().map_err(|_| bad_request(ERR_EXPIRATION_FORMAT_INVALID.to_string()))
        })
}

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
