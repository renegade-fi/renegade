//! Authentication for wallet requests based on signatures with `pk_root`

use base64::engine::{general_purpose as b64_general_purpose, Engine};
use common::types::wallet::keychain::HmacKey;
use external_api::RENEGADE_AUTH_HEADER_NAME;
use hyper::HeaderMap;

use crate::error::{bad_request, unauthorized, ApiServerError};

use super::helpers::{check_auth_timestamp, parse_sig_expiration};

/// Error displayed when the signature format is invalid
const ERR_SIG_FORMAT_INVALID: &str = "signature format invalid";
/// Error displayed when the signature header is missing
const ERR_SIG_HEADER_MISSING: &str = "signature missing from headers";
/// Error displayed when signature verification fails on a request
const ERR_SIG_VERIFICATION_FAILED: &str = "signature verification failed";

/// The signatures are over `secp256k1`, and have an expiration attached that
/// determines the duration of their validity
pub fn authenticate_wallet_request(
    headers: &HeaderMap,
    body: &[u8],
    symmetric_key: &HmacKey,
) -> Result<(), ApiServerError> {
    // Parse the signature and the expiration timestamp from the header
    let signature = parse_signature_from_header(headers)?;
    let expiration = parse_sig_expiration(headers)?;

    // Recover a public key from the byte packed scalar representing the public key
    validate_expiring_signature(body, expiration, &signature, symmetric_key)
}

/// Parse a signature from the given header
fn parse_signature_from_header(headers: &HeaderMap) -> Result<Vec<u8>, ApiServerError> {
    let b64_signature: &str = headers
        .get(RENEGADE_AUTH_HEADER_NAME)
        .ok_or_else(|| bad_request(ERR_SIG_HEADER_MISSING.to_string()))?
        .to_str()
        .map_err(|_| bad_request(ERR_SIG_FORMAT_INVALID.to_string()))?;
    b64_general_purpose::STANDARD_NO_PAD
        .decode(b64_signature)
        .map_err(|_| bad_request(ERR_SIG_FORMAT_INVALID.to_string()))
}

/// A helper to verify a signature on a request body
///
/// The signature should be a sponge of the serialized request body
/// and a unix timestamp representing the expiration of the signature. A
/// call to this method after the expiration timestamp should return false
fn validate_expiring_signature(
    body: &[u8],
    expiration_timestamp: u64,
    signature: &[u8],
    symmetric_key: &HmacKey,
) -> Result<(), ApiServerError> {
    check_auth_timestamp(expiration_timestamp)?;

    let msg_bytes = [body, &expiration_timestamp.to_le_bytes()].concat();
    let res = symmetric_key.verify_mac(&msg_bytes, signature);
    if !res {
        return Err(unauthorized(ERR_SIG_VERIFICATION_FAILED.to_string()));
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use base64::engine::{general_purpose as b64_general_purpose, Engine};
    use common::types::wallet::keychain::HmacKey;
    use external_api::{RENEGADE_AUTH_HEADER_NAME, RENEGADE_SIG_EXPIRATION_HEADER_NAME};
    use hyper::{header::HeaderValue, HeaderMap};

    use super::authenticate_wallet_request;

    /// A message to sign for testing
    const MSG: &[u8] = b"dummy";

    /// Construct a `HeaderMap` for a signature request
    fn build_headers_with_expiration(expiration: u64, auth_key: &HmacKey) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(RENEGADE_SIG_EXPIRATION_HEADER_NAME, expiration.into());

        // Sign the concatenation of the message and the expiration timestamp
        let payload = [MSG, &expiration.to_le_bytes()].concat();
        let signature = auth_key.compute_mac(&payload);
        let encoded_sig = b64_general_purpose::STANDARD_NO_PAD.encode(signature);

        headers.insert(RENEGADE_AUTH_HEADER_NAME, HeaderValue::from_str(&encoded_sig).unwrap());

        headers
    }

    /// Build a set of headers using the an expiration one second in the future
    fn build_headers(root_key: &HmacKey) -> HeaderMap {
        let current_time = util::get_current_time_millis();
        build_headers_with_expiration(current_time + 1_000, root_key)
    }

    /// Tests a valid signature on a request
    #[test]
    fn test_valid_sig() {
        let key = HmacKey::random();
        let headers = build_headers(&key);

        let res = authenticate_wallet_request(&headers, MSG, &key);
        assert!(res.is_ok());
    }

    /// Tests an invalid signature on a request
    ///
    /// This is tested by modifying the key
    #[test]
    fn test_invalid_sig() {
        let key = HmacKey::random();
        let headers = build_headers(&key);

        let different_key = HmacKey::random();
        let res = authenticate_wallet_request(&headers, MSG, &different_key);
        assert!(res.is_err());
    }

    /// Tests an expired signature on a request
    #[test]
    fn test_expired_sig() {
        let key = HmacKey::random();
        let now = util::get_current_time_millis();
        let headers = build_headers_with_expiration(now - 1, &key);

        let res = authenticate_wallet_request(&headers, MSG, &key);
        assert!(res.is_err());
    }
}
