//! Groups API types for the HTTP API

use serde::{Deserialize, Serialize};

pub mod account;
#[cfg(feature = "admin-api")]
pub mod admin;
pub mod balance;
#[cfg(feature = "external-match-api")]
pub mod external_match;
pub mod market;
pub mod metadata;
pub mod order;
pub mod task;

// -------------
// | API Types |
// -------------

/// A ping response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PingResponse {
    /// The timestamp when the response is sent
    pub timestamp: u64,
}
