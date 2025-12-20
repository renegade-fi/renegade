//! API types for the relayer's websocket and HTTP APIs
#[cfg(feature = "admin-api")]
mod admin;
#[cfg(feature = "network-api")]
mod api_network_info;
#[cfg(feature = "order-book-api")]
mod api_order_book;
#[cfg(feature = "task-api")]
mod api_task_history;
#[cfg(feature = "wallet-api")]
mod api_wallet;

#[cfg(feature = "admin-api")]
pub use admin::*;
#[cfg(feature = "network-api")]
pub use api_network_info::*;
#[cfg(feature = "order-book-api")]
pub use api_order_book::*;
#[cfg(feature = "task-api")]
pub use api_task_history::*;
#[cfg(feature = "wallet-api")]
pub use api_wallet::*;
use serde::{Deserialize, Serialize};

// -------------
// | API Types |
// -------------

/// A token in the the supported token list
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiToken {
    /// The token address
    pub address: String,
    /// The token symbol
    pub symbol: String,
}

impl ApiToken {
    /// Constructor
    pub fn new(addr: String, sym: String) -> Self {
        Self { address: addr, symbol: sym }
    }
}
