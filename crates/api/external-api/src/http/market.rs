//! HTTP route definitions and request/response types for market operations

use serde::{Deserialize, Serialize};

use crate::types::{MarketDepth, MarketInfo};

// ---------------
// | HTTP Routes |
// ---------------

/// Route to get all markets
pub const GET_MARKETS_ROUTE: &str = "/v2/markets";
/// Route to get market depths for all markets
pub const GET_MARKETS_DEPTH_ROUTE: &str = "/v2/markets/depth";
/// Route to get market depth by mint
pub const GET_MARKET_DEPTH_BY_MINT_ROUTE: &str = "/v2/markets/:mint/depth";
/// Route to get market price by mint
pub const GET_MARKET_PRICE_ROUTE: &str = "/v2/markets/:mint/price";

// -------------------
// | Request/Response |
// -------------------

/// Response for get markets
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetMarketsResponse {
    /// The markets
    pub markets: Vec<MarketInfo>,
}

/// Response for get market depths
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetMarketDepthsResponse {
    /// The market depths
    pub market_depths: Vec<MarketDepth>,
}

/// Response for get market depth by mint
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetMarketDepthByMintResponse {
    /// The market depth
    pub market_depth: MarketDepth,
}
