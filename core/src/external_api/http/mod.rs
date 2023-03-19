//! Groups API types for the HTTP API

use serde::{Deserialize, Serialize};

pub mod price_report;
pub mod order_book;
pub mod network;
pub mod wallet;

/// A ping response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PingResponse {
    /// The timestamp when the response is sent
    pub timestamp: u128,
}
