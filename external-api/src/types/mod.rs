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
