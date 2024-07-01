//! Defines common types that many crates can depend on
pub mod exchange;
pub mod gossip;
pub mod handshake;
pub mod merkle;
pub mod mpc_preprocessing;
pub mod network_order;
pub mod proof_bundles;
pub mod tasks;
pub mod token;
pub mod transfer_auth;
pub mod wallet;

// Re-export the mock types
#[cfg(feature = "mocks")]
pub use wallet::mocks as wallet_mocks;

use tokio::sync::watch::{
    channel as watch_channel, Receiver as WatchReceiver, Sender as WatchSender,
};

/// A type alias for an empty channel used to signal cancellation to workers
pub type CancelChannel = WatchReceiver<()>;
/// Create a new cancel channel
pub fn new_cancel_channel() -> (WatchSender<()>, CancelChannel) {
    watch_channel(())
}

/// An alias for the price of an asset pair that abstracts away its
/// representation
pub type Price = f64;

/// A type alias for matching pool names
pub type MatchingPoolName = String;
