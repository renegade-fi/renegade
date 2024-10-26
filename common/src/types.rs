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

use token::Token;
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

    /// Get the decimal-corrected version of this price for a given token pair
    pub fn get_decimal_corrected_price(
        self,
        base_token: &Token,
        quote_token: &Token,
    ) -> Result<TimestampedPrice, String> {
        let base_decimals = base_token
            .get_decimals()
            .ok_or(format!("No decimals for {}", base_token.get_addr()))?;
        let quote_decimals = quote_token
            .get_decimals()
            .ok_or(format!("No decimals for {}", quote_token.get_addr()))?;

        let TimestampedPrice { price: original_price, timestamp } = self;
        let decimal_diff = quote_decimals as i32 - base_decimals as i32;
        let corrected_price = original_price * 10f64.powi(decimal_diff);

        Ok(TimestampedPrice { price: corrected_price, timestamp })
    }
}

impl From<&PriceReport> for TimestampedPrice {
    fn from(value: &PriceReport) -> Self {
        Self { price: value.price, timestamp: value.local_timestamp }
    }
}

/// A type alias for matching pool names
pub type MatchingPoolName = String;
