//! Types for prices and price timestamps

use circuit_types::fixed_point::FixedPoint;
use serde::{Deserialize, Serialize};
use util::get_current_time_millis;

use crate::types::{exchange::PriceReport, token::Token};

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

/// A timestamped price that holds the price in fixed point representation
///
/// This allows the matching engine to retain exact precision for prices which
/// were computed in fixed point
///
/// We also allow conversion to the more readable `TimestampedPrice` type used
/// throughout the relayer
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TimestampedPriceFp {
    /// The price
    pub price: FixedPoint,
    /// The time the price was sampled, in milliseconds since the epoch
    pub timestamp: u64,
}

impl TimestampedPriceFp {
    /// Create a new timestamped fixed point price
    pub fn new(price: FixedPoint) -> Self {
        let timestamp = get_current_time_millis();
        Self { price, timestamp }
    }

    /// Get the underlying price as a fixed point number
    pub fn price(&self) -> FixedPoint {
        self.price
    }
}

impl From<TimestampedPrice> for TimestampedPriceFp {
    fn from(ts_price: TimestampedPrice) -> Self {
        let price_fp = FixedPoint::from_f64_round_down(ts_price.price);
        Self { price: price_fp, timestamp: ts_price.timestamp }
    }
}

impl From<TimestampedPriceFp> for TimestampedPrice {
    fn from(ts_price: TimestampedPriceFp) -> Self {
        Self { price: ts_price.price.to_f64(), timestamp: ts_price.timestamp }
    }
}
