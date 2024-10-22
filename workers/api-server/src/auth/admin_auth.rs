//! Authentication for admin API

use common::types::wallet::keychain::HmacKey;
use hyper::HeaderMap;

use crate::error::{unauthorized, ApiServerError};

use super::helpers::{
    check_auth_timestamp, compute_expiring_hmac, parse_hmac, parse_sig_expiration,
};

/// Error message emitted when the HMAC is invalid
const ERR_HMAC_INVALID: &str = "HMAC invalid";

/// Authenticate an admin request
pub fn authenticate_admin_request(
    key: &HmacKey,
    headers: &HeaderMap,
    payload: &[u8],
) -> Result<(), ApiServerError> {
    // Parse the MAC and expiration timestamp
    let caller_mac = parse_hmac(headers)?;
    let expiration = parse_sig_expiration(headers)?;

    // Check the timestamp and the mac
    check_auth_timestamp(expiration)?;

    // Compute the HMAC of the request
    let expected_mac = compute_expiring_hmac(key, payload, expiration);
    if caller_mac.to_vec() != expected_mac {
        return Err(unauthorized(ERR_HMAC_INVALID.to_string()));
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use base64::{engine::general_purpose as b64_general_purpose, Engine as B64Engine};
    use common::types::wallet::keychain::HmacKey;
    use hyper::{header::HeaderValue, HeaderMap};

    use crate::auth::helpers::{
        RENEGADE_AUTH_HMAC_HEADER_NAME, RENEGADE_SIG_EXPIRATION_HEADER_NAME,
    };

    use super::authenticate_admin_request;

    /// A message to sign for testing
    const MSG: &[u8] = b"dummy";

    /// Construct a `HeaderMap` for an authenticated admin request
    fn build_headers_with_expiration(expiration: u64, key: &HmacKey) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(RENEGADE_SIG_EXPIRATION_HEADER_NAME, expiration.into());

        // Authenticate the concatenation of the message and the expiration timestamp
        let payload = [MSG, &expiration.to_le_bytes()].concat();
        let hmac = key.compute_mac(&payload);
        let encoded_hmac = b64_general_purpose::STANDARD_NO_PAD.encode(hmac);

        headers
            .insert(RENEGADE_AUTH_HMAC_HEADER_NAME, HeaderValue::from_str(&encoded_hmac).unwrap());

        headers
    }

    /// Build a set of headers using the an expiration one second in the future
    fn build_headers(key: &HmacKey) -> HeaderMap {
        let current_time = util::get_current_time_millis();
        build_headers_with_expiration(current_time + 1_000, key)
    }

    /// Tests a valid signature on a request
    #[test]
    fn test_valid_sig() {
        let key = HmacKey::random();
        let headers = build_headers(&key);

        let res = authenticate_admin_request(&key, &headers, MSG);
        assert!(res.is_ok());
    }

    /// Tests an invalid signature on a request
    ///
    /// This is tested by modifying the key
    #[test]
    fn test_invalid_sig() {
        let key = HmacKey::random();
        let headers = build_headers(&key);

        let new_key = HmacKey::random();
        let res = authenticate_admin_request(&new_key, &headers, MSG);
        assert!(res.is_err());
    }

    /// Tests an expired signature on a request
    #[test]
    fn test_expired_sig() {
        let key = HmacKey::random();
        let now = util::get_current_time_millis();
        let headers = build_headers_with_expiration(now - 1, &key);

        let res = authenticate_admin_request(&key, &headers, MSG);
        assert!(res.is_err());
    }
}
