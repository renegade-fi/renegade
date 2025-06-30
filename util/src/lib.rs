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
#[cfg(feature = "errors")]
pub mod errors;
#[cfg(feature = "hex")]
pub mod hex;
#[cfg(feature = "matching-engine")]
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
