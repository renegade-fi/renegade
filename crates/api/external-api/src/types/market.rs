//! API types for markets

use serde::{Deserialize, Serialize};

use super::external_match::{ApiTimestampedPrice, FeeTakeRate};

// ---------------
// | Token Types |
// ---------------

/// A token in the supported token list
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiToken {
    /// The token address
    pub address: String,
    /// The token symbol
    pub symbol: String,
}

impl ApiToken {
    /// Constructor
    pub fn new(addr: String, sym: String) -> Self {
        Self { address: addr, symbol: sym }
    }
}

// ----------------
// | Market Types |
// ----------------

/// Information about a market
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MarketInfo {
    /// The base token
    pub base: ApiToken,
    /// The quote token
    pub quote: ApiToken,
    /// The current price
    pub price: ApiTimestampedPrice,
    /// The fee rates for internal matches
    pub internal_match_fee_rates: FeeTakeRate,
    /// The fee rates for external matches
    pub external_match_fee_rates: FeeTakeRate,
}

/// The depth of a market
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MarketDepth {
    /// The market information
    pub market: MarketInfo,
    /// The buy side depth
    pub buy: DepthSide,
    /// The sell side depth
    pub sell: DepthSide,
}

/// One side of the depth book
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DepthSide {
    /// The total quantity
    pub total_quantity: String,
    /// The total quantity in USD
    pub total_quantity_usd: String,
}
