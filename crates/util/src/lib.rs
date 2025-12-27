//! Defines one-off utility functions used throughout the node
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![feature(ip)]

use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "channels")]
pub mod channels;
#[cfg(feature = "concurrency")]
pub mod concurrency;
mod default_wrapper;
pub use default_wrapper::*;
#[cfg(feature = "errors")]
pub mod errors;
#[cfg(any(feature = "hex", feature = "hex-core"))]
pub mod hex;
#[cfg(all(feature = "matching-engine", feature = "v1"))]
pub mod matching_engine;
#[cfg(feature = "networking")]
pub mod networking;
#[cfg(feature = "blockchain")]
pub mod on_chain;
#[cfg(feature = "serde")]
pub mod serde;
#[cfg(feature = "telemetry")]
pub mod telemetry;

/// Returns the current unix timestamp in seconds, represented as u64
pub fn get_current_time_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("negative timestamp").as_secs()
}

/// Returns the current unix timestamp in milliseconds, represented as u64
pub fn get_current_time_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("negative timestamp").as_millis() as u64
}
