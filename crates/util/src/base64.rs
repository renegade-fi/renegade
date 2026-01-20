//! Helpers for converting values to and from base64 strings

use base64::engine::{Engine, general_purpose::STANDARD_NO_PAD as BASE64_ENGINE};

/// Decode a base64 string to a vector of bytes
pub fn bytes_from_base64_string(base64: &str) -> Result<Vec<u8>, String> {
    BASE64_ENGINE
        .decode(base64)
        .map_err(|e| format!("error deserializing bytes from base64 string: {e}"))
}
