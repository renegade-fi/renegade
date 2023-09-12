//! Defines the access patterns and interface to the durable storage layer
//! concretely implemented as an `mdbx` instance

use std::borrow::Cow;

pub mod cursor;
pub mod db;
pub mod error;
pub mod traits;

/// A type alias used for reading from the database
type CowBuffer<'a> = Cow<'a, [u8]>;
