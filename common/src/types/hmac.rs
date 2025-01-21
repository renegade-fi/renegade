//! Types and utilities for HMAC keys

use base64::engine::{general_purpose as b64_general_purpose, Engine};
use hmac::Mac;
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use util::hex::{bytes_from_hex_string, bytes_to_hex_string};

/// The length of an HMAC key in bytes
pub const HMAC_KEY_LEN: usize = 32;

/// Type alias for the hmac core implementation
type HmacSha256 = hmac::Hmac<Sha256>;

/// A type representing a symmetric HMAC key
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HmacKey(pub [u8; HMAC_KEY_LEN]);
impl HmacKey {
    /// Create a new HMAC key from a hex string
    pub fn new(hex: &str) -> Result<Self, String> {
        Self::from_hex_string(hex)
    }

    /// Get the inner bytes
    pub fn inner(&self) -> &[u8; HMAC_KEY_LEN] {
        &self.0
    }

    /// Create a new random HMAC key
    pub fn random() -> Self {
        let mut rng = thread_rng();
        let mut bytes = [0; HMAC_KEY_LEN];
        rng.fill_bytes(&mut bytes);

        Self(bytes)
    }

    /// Convert the HMAC key to a hex string
    pub fn to_hex_string(&self) -> String {
        bytes_to_hex_string(&self.0)
    }

    /// Try to convert a hex string to an HMAC key
    pub fn from_hex_string(hex: &str) -> Result<Self, String> {
        let bytes = bytes_from_hex_string(hex)?;
        if bytes.len() != HMAC_KEY_LEN {
            return Err(format!("expected {HMAC_KEY_LEN} byte HMAC key, got {}", bytes.len()));
        }

        Ok(Self(bytes.try_into().unwrap()))
    }

    /// Convert the HMAC key to a base64 string
    pub fn to_base64_string(&self) -> String {
        b64_general_purpose::STANDARD.encode(self.0)
    }

    /// Try to convert a base64 string to an HMAC key
    pub fn from_base64_string(base64: &str) -> Result<Self, String> {
        let bytes = b64_general_purpose::STANDARD.decode(base64).map_err(|e| e.to_string())?;
        if bytes.len() != HMAC_KEY_LEN {
            return Err(format!("expected {HMAC_KEY_LEN} byte HMAC key, got {}", bytes.len()));
        }

        Ok(Self(bytes.try_into().unwrap()))
    }

    /// Compute the HMAC of a message
    pub fn compute_mac(&self, msg: &[u8]) -> Vec<u8> {
        let mut hmac =
            HmacSha256::new_from_slice(self.inner()).expect("hmac can handle all slice lengths");
        hmac.update(msg);
        hmac.finalize().into_bytes().to_vec()
    }

    /// Verify the HMAC of a message
    pub fn verify_mac(&self, msg: &[u8], mac: &[u8]) -> bool {
        self.compute_mac(msg) == mac
    }
}
