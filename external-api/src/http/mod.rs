//! Groups API types for the HTTP API

use serde::{Deserialize, Serialize};

#[cfg(feature = "admin-api")]
pub mod admin;
#[cfg(feature = "external-match-api")]
pub mod external_match;
#[cfg(feature = "network-api")]
pub mod network;
#[cfg(feature = "order-book-api")]
pub mod order_book;
#[cfg(feature = "full-api")]
pub mod price_report;
#[cfg(feature = "task-api")]
pub mod task;
#[cfg(feature = "task-api")]
pub mod task_history;
#[cfg(feature = "wallet-api")]
pub mod wallet;

/// A ping response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PingResponse {
    /// The timestamp when the response is sent
    pub timestamp: u64,
}
