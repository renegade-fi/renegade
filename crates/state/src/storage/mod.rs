//! Defines the access patterns and interface to the durable storage layer
//! concretely implemented as an `mdbx` instance

pub mod archived_value;
pub mod cursor;
pub mod db;
pub mod error;
pub mod traits;
pub mod tx;

pub use archived_value::{ArchivedValue, CowBuffer};
