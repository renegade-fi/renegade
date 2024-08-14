//! Groups API types for the HTTP API

use serde::{Deserialize, Serialize};

pub mod admin;
pub mod network;
pub mod order_book;
pub mod price_report;
pub mod task;
pub mod task_history;
pub mod wallet;

/// A ping response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PingResponse {
    /// The timestamp when the response is sent
    pub timestamp: u64,
}
