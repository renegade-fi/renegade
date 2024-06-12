//! Authentication for admin API

use base64::engine::{general_purpose as b64_general_purpose, Engine};
use common::types::gossip::SymmetricAuthKey;
use external_api::RENEGADE_AUTH_HMAC_HEADER_NAME;
use hmac::Mac;
use hyper::HeaderMap;
use sha2::Sha256;

use crate::error::{bad_request, unauthorized, ApiServerError};

use super::{
    helpers::{check_auth_timestamp, parse_sig_expiration},
    HMAC_LEN,
};

/// Type alias for the hmac core implementation
type HmacSha256 = hmac::Hmac<Sha256>;

/// Error message emitted when the HMAC is missing from the request
const ERR_HMAC_MISSING: &str = "HMAC is missing from the request";
/// Error message emitted when the format of an HMAC is invalid
const ERR_HMAC_FORMAT_INVALID: &str = "HMAC format invalid";
/// Error message emitted when the HMAC is invalid
const ERR_HMAC_INVALID: &str = "HMAC invalid";

/// Authenticate an admin request
pub fn authenticate_admin_request(
    key: SymmetricAuthKey,
    headers: &HeaderMap,
    payload: &[u8],
) -> Result<(), ApiServerError> {
    // Parse the MAC and expiration timestamp
    let caller_mac = parse_hmac(headers)?;
    let expiration = parse_sig_expiration(headers)?;

    // Check the timestamp and the mac
    check_auth_timestamp(expiration)?;

    // Check the MAC on the payload concatenated with the expiration timestamp
    let mut hmac = HmacSha256::new_from_slice(&key).expect("hmac can handle all slice lengths");
    let msg_bytes = [payload, &expiration.to_le_bytes()].concat();
    hmac.update(&msg_bytes);
    let mac = hmac.finalize().into_bytes().to_vec();

    if caller_mac.to_vec() != mac {
        return Err(unauthorized(ERR_HMAC_INVALID.to_string()));
    }

    Ok(())
}

/// Parse an HMAC from headers
fn parse_hmac(headers: &HeaderMap) -> Result<[u8; HMAC_LEN], ApiServerError> {
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

#[cfg(test)]
mod test {
    use base64::engine::{general_purpose as b64_general_purpose, Engine};
    use common::types::gossip::SymmetricAuthKey;
    use external_api::{RENEGADE_AUTH_HMAC_HEADER_NAME, RENEGADE_SIG_EXPIRATION_HEADER_NAME};
    use hmac::Mac;
    use hyper::{header::HeaderValue, HeaderMap};
    use rand::{thread_rng, RngCore};

    use crate::auth::HMAC_LEN;

    use super::{authenticate_admin_request, HmacSha256};

    /// A message to sign for testing
    const MSG: &[u8] = b"dummy";

    /// Get a random symmetric key for testing
    fn random_key() -> SymmetricAuthKey {
        let mut rng = thread_rng();
        let mut key = [0; 32];
        rng.fill_bytes(&mut key);

        key
    }

    /// Create an hmac of a message
    fn create_hmac(key: &SymmetricAuthKey, msg: &[u8]) -> [u8; HMAC_LEN] {
        let mut hmac = HmacSha256::new_from_slice(key).unwrap();
        hmac.update(msg);

        hmac.finalize().into_bytes().to_vec().try_into().unwrap()
    }

    /// Construct a `HeaderMap` for an authenticated admin request
    fn build_headers_with_expiration(expiration: u64, key: &SymmetricAuthKey) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(RENEGADE_SIG_EXPIRATION_HEADER_NAME, expiration.into());

        // Authenticate the concatenation of the message and the expiration timestamp
        let payload = [MSG, &expiration.to_le_bytes()].concat();
        let hmac = create_hmac(key, &payload);
        let encoded_hmac = b64_general_purpose::STANDARD_NO_PAD.encode(hmac);

        headers
            .insert(RENEGADE_AUTH_HMAC_HEADER_NAME, HeaderValue::from_str(&encoded_hmac).unwrap());

        headers
    }

    /// Build a set of headers using the an expiration one second in the future
    fn build_headers(key: &SymmetricAuthKey) -> HeaderMap {
        let current_time = util::get_current_time_millis();
        build_headers_with_expiration(current_time + 1_000, key)
    }

    /// Tests a valid signature on a request
    #[test]
    fn test_valid_sig() {
        let key = random_key();
        let headers = build_headers(&key);

        let res = authenticate_admin_request(key, &headers, MSG);
        assert!(res.is_ok());
    }

    /// Tests an invalid signature on a request
    ///
    /// This is tested by modifying the key
    #[test]
    fn test_invalid_sig() {
        let key = random_key();
        let headers = build_headers(&key);

        let res = authenticate_admin_request(random_key(), &headers, MSG);
        assert!(res.is_err());
    }

    /// Tests an expired signature on a request
    #[test]
    fn test_expired_sig() {
        let key = random_key();
        let now = util::get_current_time_millis();
        let headers = build_headers_with_expiration(now - 1, &key);

        let res = authenticate_admin_request(key, &headers, MSG);
        assert!(res.is_err());
    }
}
