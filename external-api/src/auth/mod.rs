//! Auth helpers for the external API
mod auth_helpers;
mod error;

// Re-export the public interface
pub use auth_helpers::*;
pub use error::*;

/// The number of bytes in an HMAC
pub const HMAC_LEN: usize = 32;
