//! Defines state migrations to initialize the node's global state
//!
//! A state migration may, for example, fixup missing data, backfill a
//! denormalized table, or prune stale state entries
//!
//! These migrations should be idempotent, and defined as need be

mod remove_old_task_queues;
mod remove_phantom_orders;
pub(crate) use remove_old_task_queues::remove_old_queues;
pub(crate) use remove_phantom_orders::remove_phantom_orders;
