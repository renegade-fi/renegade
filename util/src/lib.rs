//! Defines one-off utility functions used throughout the node
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![feature(ip)]
#![feature(generic_const_exprs)]

use std::time::{SystemTime, UNIX_EPOCH};

pub mod arbitrum;
pub mod logging;
pub mod matching_engine;
pub mod networking;
pub mod runtime;

/// Returns the current unix timestamp in seconds, represented as u64
pub fn get_current_time_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("negative timestamp").as_secs()
}

/// Returns the current unix timestamp in milliseconds, represented as u64
pub fn get_current_time_millis() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("negative timestamp").as_millis()
}
