//! Defines one-off utility functions used throughout the node
#![feature(ip)]
#![allow(incomplete_features)]

use std::time::{SystemTime, UNIX_EPOCH};

pub mod networking;
pub mod runtime;

/// Returns the current unix timestamp in seconds, represented as u64
pub fn get_current_time_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("negative timestamp")
        .as_secs()
}
