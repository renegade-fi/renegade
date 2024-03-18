//! Groups API types for the HTTP API

use serde::{Deserialize, Serialize};

pub mod network;
pub mod order_book;
pub mod price_report; // TODO: REMOVE AFTER FE INTEGRATION W/ STANDALONE PRICE REPORTER
pub mod task;
pub mod wallet;

/// A ping response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PingResponse {
    /// The timestamp when the response is sent
    pub timestamp: u128,
}
