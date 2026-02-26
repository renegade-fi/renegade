//! API types for markets

use alloy::primitives::Address;
use circuit_types::Amount;
use serde::{Deserialize, Serialize};
#[cfg(feature = "full-api")]
use types_core::Token;

use super::external_match::{ApiTimestampedPrice, FeeTakeRate};
use crate::serde_helpers::{self, address_as_string};

// ---------------
// | Token Types |
// ---------------

/// A token in the supported token list
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiToken {
    /// The token address
    #[serde(with = "address_as_string")]
    pub address: Address,
    /// The token symbol
    pub symbol: String,
}

impl ApiToken {
    /// Constructor
    pub fn new(addr: Address, sym: String) -> Self {
        Self { address: addr, symbol: sym }
    }
}

#[cfg(feature = "full-api")]
impl From<Token> for ApiToken {
    fn from(token: Token) -> Self {
        let symbol = token.get_ticker().unwrap_or_default();
        let address = token.get_alloy_address();
        Self::new(address, symbol)
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
    /// The total quantity in base token units
    #[serde(with = "serde_helpers::amount_as_string")]
    pub total_quantity: Amount,
    /// The total quantity in USD
    #[serde(with = "serde_helpers::f64_as_string")]
    pub total_quantity_usd: f64,
}
