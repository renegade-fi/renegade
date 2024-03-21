//! Defines authentication primitives for the API server

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::{general_purpose as b64_general_purpose, Engine};
use circuit_types::keychain::PublicSigningKey;
use external_api::{RENEGADE_AUTH_HEADER_NAME, RENEGADE_SIG_EXPIRATION_HEADER_NAME};
use hyper::HeaderMap;
use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

use crate::error::{bad_request, unauthorized, ApiServerError};

/// Error displayed when the signature format is invalid
const ERR_SIG_FORMAT_INVALID: &str = "signature format invalid";
/// Error displayed when the signature header is missing
const ERR_SIG_HEADER_MISSING: &str = "signature missing from headers";
/// Error displayed when the signature expiration header is missing
const ERR_SIG_EXPIRATION_MISSING: &str = "signature expiration missing from headers";
/// Error displayed when the expiration format is invalid
const ERR_EXPIRATION_FORMAT_INVALID: &str = "could not parse signature expiration timestamp";
/// Error displayed when a signature has expired
const ERR_EXPIRED: &str = "signature expired";
/// Error displayed when signature verification fails on a request
const ERR_SIG_VERIFICATION_FAILED: &str = "signature verification failed";

/// Authenticates a wallet request using the given key
///
/// The signatures are over `secp256k1`, and have an expiration attached that
/// determines the duration of their validity
pub fn authenticate_wallet_request(
    headers: &HeaderMap,
    body: &[u8],
    pk_root: &PublicSigningKey,
) -> Result<(), ApiServerError> {
    // Parse the signature and the expiration timestamp from the header
    let signature = parse_signature_from_header(headers)?;
    let sig_expiration = headers
        .get(RENEGADE_SIG_EXPIRATION_HEADER_NAME)
        .ok_or_else(|| bad_request(ERR_SIG_EXPIRATION_MISSING.to_string()))?;

    // Parse the expiration into a timestamp
    let expiration = sig_expiration
        .to_str()
        .map_err(|_| bad_request(ERR_EXPIRATION_FORMAT_INVALID.to_string()))
        .and_then(|s| {
            s.parse::<u64>().map_err(|_| bad_request(ERR_EXPIRATION_FORMAT_INVALID.to_string()))
        })?;

    // Recover a public key from the byte packed scalar representing the public key
    let root_key: VerifyingKey = pk_root.into();
    validate_expiring_signature(body, expiration, &signature, &root_key)
}

/// Parse a signature from the given header
fn parse_signature_from_header(headers: &HeaderMap) -> Result<Signature, ApiServerError> {
    let b64_signature: &str = headers
        .get(RENEGADE_AUTH_HEADER_NAME)
        .ok_or_else(|| bad_request(ERR_SIG_HEADER_MISSING.to_string()))?
        .to_str()
        .map_err(|_| bad_request(ERR_SIG_FORMAT_INVALID.to_string()))?;
    let sig_bytes = b64_general_purpose::STANDARD_NO_PAD
        .decode(b64_signature)
        .map_err(|_| bad_request(ERR_SIG_FORMAT_INVALID.to_string()))?;

    Signature::from_slice(&sig_bytes).map_err(|_| bad_request(ERR_SIG_FORMAT_INVALID.to_string()))
}

/// A helper to verify a signature on a request body
///
/// The signature should be a sponge of the serialized request body
/// and a unix timestamp representing the expiration of the signature. A
/// call to this method after the expiration timestamp should return false
fn validate_expiring_signature(
    body: &[u8],
    expiration_timestamp: u64,
    signature: &Signature,
    pk_root: &VerifyingKey,
) -> Result<(), ApiServerError> {
    // Check the expiration timestamp
    let now = SystemTime::now();
    let target_duration = Duration::from_millis(expiration_timestamp);
    let target_time = UNIX_EPOCH + target_duration;

    if now >= target_time {
        return Err(unauthorized(ERR_EXPIRED.to_string()));
    }

    let msg_bytes = [body, &expiration_timestamp.to_le_bytes()].concat();
    pk_root
        .verify(&msg_bytes, signature)
        .map_err(|_| unauthorized(ERR_SIG_VERIFICATION_FAILED.to_string()))
}

#[cfg(test)]
mod test {
    use base64::engine::{general_purpose as b64_general_purpose, Engine};
    use external_api::{RENEGADE_AUTH_HEADER_NAME, RENEGADE_SIG_EXPIRATION_HEADER_NAME};
    use hyper::{header::HeaderValue, HeaderMap};
    use k256::ecdsa::{signature::Signer, Signature, SigningKey};
    use rand::thread_rng;

    use super::authenticate_wallet_request;

    /// A message to sign for testing
    const MSG: &[u8] = b"dummy";

    /// Get a random verifying key for testing
    fn random_key() -> SigningKey {
        let mut rng = thread_rng();
        SigningKey::random(&mut rng)
    }

    /// Construct a `HeaderMap` for a signature request
    fn build_headers_with_expiration(expiration: u64, root_key: &SigningKey) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(RENEGADE_SIG_EXPIRATION_HEADER_NAME, expiration.into());

        // Sign the concatenation of the message and the expiration timestamp
        let payload = [MSG, &expiration.to_le_bytes()].concat();
        let signature: Signature = root_key.sign(&payload);
        let encoded_sig = b64_general_purpose::STANDARD_NO_PAD.encode(signature.to_bytes());

        headers.insert(RENEGADE_AUTH_HEADER_NAME, HeaderValue::from_str(&encoded_sig).unwrap());

        headers
    }

    /// Build a set of headers using the an expiration one second in the future
    fn build_headers(root_key: &SigningKey) -> HeaderMap {
        let current_time = util::get_current_time_millis() as u64;
        build_headers_with_expiration(current_time + 1_000, root_key)
    }

    /// Tests a valid signature on a request
    #[test]
    fn test_valid_sig() {
        let key: SigningKey = random_key();
        let headers = build_headers(&key);

        let res = authenticate_wallet_request(&headers, MSG, &key.verifying_key().into());
        assert!(res.is_ok());
    }

    /// Tests an invalid signature on a request
    ///
    /// This is tested by modifying the key
    #[test]
    fn test_invalid_sig() {
        let key: SigningKey = random_key();
        let headers = build_headers(&key);

        let res = authenticate_wallet_request(&headers, MSG, &random_key().verifying_key().into());
        assert!(res.is_err());
    }

    /// Tests an expired signature on a request
    #[test]
    fn test_expired_sig() {
        let key: SigningKey = random_key();
        let now = util::get_current_time_millis() as u64;
        let headers = build_headers_with_expiration(now - 1, &key);

        let res = authenticate_wallet_request(&headers, MSG, &key.verifying_key().into());
        assert!(res.is_err());
    }
}
