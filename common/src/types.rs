//! Defines common types that many crates can depend on

// --- Internal Types --- //
#[cfg(feature = "internal-types")]
pub mod gossip;
#[cfg(feature = "internal-types")]
pub mod handshake;
#[cfg(feature = "internal-types")]
pub mod network_order;
#[cfg(feature = "internal-types")]
pub mod proof_bundles;
#[cfg(feature = "internal-types")]
pub mod tasks;
#[cfg(feature = "internal-types")]
pub mod transfer_auth;

// --- External Types --- //
pub mod chain;
pub mod exchange;
#[cfg(feature = "hmac")]
pub mod hmac;
#[cfg(feature = "wallet")]
pub mod merkle;
pub mod price;
pub mod token;
#[cfg(feature = "wallet")]
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

/// A type alias for matching pool names
pub type MatchingPoolName = String;
