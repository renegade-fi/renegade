//! Error types for authentication helpers

use thiserror::Error;

/// Error type for authentication helpers
#[derive(Error, Debug)]
pub enum AuthError {
    /// Error displayed when the signature is invalid
    #[error("invalid signature")]
    InvalidSignature,
    /// Error displayed when the expiration format is invalid
    #[error("could not parse signature expiration timestamp")]
    ExpirationFormatInvalid,
    /// Error displayed when the HMAC is missing from the request
    #[error("HMAC is missing from the request")]
    HmacMissing,
    /// Error displayed when the HMAC format is invalid
    #[error("HMAC format invalid")]
    HmacFormatInvalid,
    /// Error displayed when the signature expiration header is missing
    #[error("signature expiration missing from headers")]
    SignatureExpirationMissing,
    /// Error displayed when a signature has expired
    #[error("signature expired")]
    SignatureExpired,
}
