//! Types for prices and price timestamps

use std::time::{SystemTime, UNIX_EPOCH};

use circuit_types::fixed_point::FixedPoint;
#[cfg(feature = "rkyv")]
use darkpool_types::rkyv_remotes::FixedPointDef;
use serde::{Deserialize, Serialize};

use crate::exchange::PriceReport;
use crate::token::Token;

/// An alias for the price of an asset pair that abstracts away its
/// representation
pub type Price = f64;

/// Returns the current unix timestamp in milliseconds
fn get_current_time_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("negative timestamp").as_millis() as u64
}

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

/// A price along with the time it was sampled represented as a fixed point
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct TimestampedPriceFp {
    /// The price
    #[cfg_attr(feature = "rkyv", rkyv(with = FixedPointDef))]
    pub price: FixedPoint,
    /// The time the price was sampled, in milliseconds since the epoch
    pub timestamp: u64,
}

impl From<TimestampedPrice> for TimestampedPriceFp {
    fn from(value: TimestampedPrice) -> Self {
        let price = FixedPoint::from_f64_round_down(value.price);
        Self { price, timestamp: value.timestamp }
    }
}

impl From<TimestampedPriceFp> for TimestampedPrice {
    fn from(value: TimestampedPriceFp) -> Self {
        Self { price: value.price.to_f64(), timestamp: value.timestamp }
    }
}

impl From<FixedPoint> for TimestampedPriceFp {
    fn from(price: FixedPoint) -> Self {
        let timestamp = get_current_time_millis();
        Self { price, timestamp }
    }
}
