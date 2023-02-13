//! Groups state object definitions and handles logic for serializing access to shared
//! global state elements
mod orderbook;
pub mod peers;
#[allow(clippy::module_inception)]
mod state;
pub mod wallet;

pub use self::orderbook::{NetworkOrder, NetworkOrderBook, NetworkOrderState, OrderIdentifier};
pub use self::state::*;
