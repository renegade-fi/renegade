//! Matching engine implementations for the handshake manager

use state::caching::order_cache::OrderBookFilter;
use types_account::account::order::Order;

// pub mod external_engine;
// pub mod internal_engine;
mod match_helpers;

/// Build a matching order filter from a given order
fn matching_order_filter(order: &Order, external: bool) -> OrderBookFilter {
    OrderBookFilter::new(order.pair(), external)
}
