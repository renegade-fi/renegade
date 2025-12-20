//! Matching engine implementations for the handshake manager

use common::types::wallet::Order;
use state::caching::order_cache::OrderBookFilter;

pub mod external_engine;
pub mod internal_engine;
mod match_helpers;
pub mod mpc_engine;

/// Build a matching order filter from a given order
fn matching_order_filter(order: &Order, external: bool) -> OrderBookFilter {
    OrderBookFilter::new(order.pair(), order.side.opposite(), external)
}
