//! Groups API types for order book API operations

use common::types::Price;
use serde::{Deserialize, Serialize};

use crate::types::{ApiNetworkOrder, DepthSide};

// ---------------
// | HTTP Routes |
// ---------------

/// Returns all known network orders
pub const GET_NETWORK_ORDERS_ROUTE: &str = "/v0/order_book/orders";
/// Returns the network order information of the specified order
pub const GET_NETWORK_ORDER_BY_ID_ROUTE: &str = "/v0/order_book/orders/:order_id";
/// Returns the external match fee for a given asset
pub const GET_EXTERNAL_MATCH_FEE_ROUTE: &str = "/v0/order_book/external-match-fee";
/// Route to get the liquidity depth of a given mint
pub const GET_DEPTH_BY_MINT_ROUTE: &str = "/v0/order_book/depth/:mint";
/// Route to get the liquidity depth for all supported pairs
pub const GET_DEPTH_FOR_ALL_PAIRS_ROUTE: &str = "/v0/order_book/depth";

// -------------
// | API Types |
// -------------

/// The response type to fetch all the known orders in the network
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetNetworkOrdersResponse {
    /// The orders known to the local peer
    pub orders: Vec<ApiNetworkOrder>,
}

/// The response type to fetch a given network order by its ID
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetNetworkOrderByIdResponse {
    /// The requested network order
    pub order: ApiNetworkOrder,
}

/// The response type to fetch the fee on a given asset
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetExternalMatchFeeResponse {
    /// The relayer fee on the given asset
    pub relayer_fee: String,
    /// The protocol fee on the given asset
    pub protocol_fee: String,
}

impl GetExternalMatchFeeResponse {
    /// Get the total fee
    pub fn total(&self) -> f64 {
        let relayer_fee = self.relayer_fee.parse::<f64>().unwrap();
        let protocol_fee = self.protocol_fee.parse::<f64>().unwrap();
        relayer_fee + protocol_fee
    }
}

/// Response for the GET /order_book/depth/:mint route
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetDepthByMintResponse {
    /// The liquidity depth for the given mint
    #[serde(flatten)]
    pub depth: PriceAndDepth,
}

/// Response for the GET /order_book/depth route
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetDepthForAllPairsResponse {
    /// The liquidity depth for all supported pairs
    pub pairs: Vec<PriceAndDepth>,
}

/// The liquidity depth for a given pair
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PriceAndDepth {
    /// The token address
    pub address: String,
    /// The current price of the token in USD
    pub price: Price,
    /// The timestamp of the price
    pub timestamp: u64,
    /// The liquidity depth for the buy side
    pub buy: DepthSide,
    /// The liquidity depth for the sell side
    pub sell: DepthSide,
}
