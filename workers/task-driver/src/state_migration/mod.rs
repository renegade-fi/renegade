//! Defines state migrations to initialize the node's global state
//!
//! A state migration may, for example, fixup missing data, backfill a
//! denormalized table, or prune stale state entries
//!
//! These migrations should be idempotent, and defined as need be

mod purge_historical_state;
mod remove_phantom_orders;
pub(crate) use purge_historical_state::purge_historical_state;
pub(crate) use remove_phantom_orders::remove_phantom_orders;
