//! Defines one-off utility functions used throughout the node
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![feature(ip)]

use std::time::{SystemTime, UNIX_EPOCH};

pub mod logging;
pub mod matching_engine;
pub mod networking;
pub mod runtime;
pub mod starknet;

/// Returns the current unix timestamp in seconds, represented as u64
pub fn get_current_time_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("negative timestamp").as_secs()
}
