//! Defines common types that many crates can depend on

use circuit_types::fixed_point::FixedPoint;
use serde::{Deserialize, Serialize};

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

use util::get_current_time_millis;
// Re-export the mock types
#[cfg(feature = "mocks")]
pub use wallet::mocks as wallet_mocks;

use tokio::sync::watch::{
    channel as watch_channel, Receiver as WatchReceiver, Sender as WatchSender,
};

use self::exchange::PriceReport;

/// A type alias for an empty channel used to signal cancellation to workers
pub type CancelChannel = WatchReceiver<()>;
/// Create a new cancel channel
pub fn new_cancel_channel() -> (WatchSender<()>, CancelChannel) {
    watch_channel(())
}

/// An alias for the price of an asset pair that abstracts away its
/// representation
pub type Price = f64;

/// A price along with the time it was sampled
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TimestampedPrice {
    /// The price
    pub price: Price,
    /// The time the price was sampled, in milliseconds since the epoch
    pub timestamp: u64,
}

impl TimestampedPrice {
    /// Create a new timestamped price
    pub fn new(price: Price) -> Self {
        let timestamp = get_current_time_millis();
        Self { price, timestamp }
    }

    /// Get the price as a fixed point number
    pub fn as_fixed_point(&self) -> FixedPoint {
        FixedPoint::from_f64_round_down(self.price)
    }
}

impl From<&PriceReport> for TimestampedPrice {
    fn from(value: &PriceReport) -> Self {
        Self { price: value.price, timestamp: value.local_timestamp }
    }
}

/// A type alias for matching pool names
pub type MatchingPoolName = String;
