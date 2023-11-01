//! Defines common types that many crates can depend on
pub mod chain_id;
pub mod exchange;
pub mod gossip;
pub mod handshake;
pub mod merkle;
pub mod network_order;
pub mod proof_bundles;
pub mod tasks;
pub mod token;
pub mod wallet;

// Re-export the mock types
#[cfg(feature = "mocks")]
pub use wallet::mocks as wallet_mocks;

use tokio::sync::watch::Receiver as WatchReceiver;

/// A type alias for an empty channel used to signal cancellation to workers
pub type CancelChannel = WatchReceiver<()>;

/// An alias for the price of an asset pair that abstracts away its
/// representation
pub type Price = f64;
