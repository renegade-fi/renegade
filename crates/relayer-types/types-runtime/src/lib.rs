//! Runtime types for the Renegade relayer
//!
//! This crate provides worker abstractions and runtime utilities.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![deny(clippy::missing_docs_in_private_items)]

mod worker;

pub use worker::*;

use tokio::sync::watch::{
    Receiver as WatchReceiver, Sender as WatchSender, channel as watch_channel,
};

/// A type alias for an empty channel used to signal cancellation to workers
pub type CancelChannel = WatchReceiver<()>;

/// Create a new cancel channel
pub fn new_cancel_channel() -> (WatchSender<()>, CancelChannel) {
    watch_channel(())
}

/// A type alias for matching pool names
pub type MatchingPoolName = String;
