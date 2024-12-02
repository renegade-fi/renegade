//! Groups API types for order book API operations

use serde::{Deserialize, Serialize};

use crate::types::{ApiNetworkOrder, ApiToken};

// ---------------
// | HTTP Routes |
// ---------------

/// Returns all known network orders
pub const GET_NETWORK_ORDERS_ROUTE: &str = "/v0/order_book/orders";
/// Returns the network order information of the specified order
pub const GET_NETWORK_ORDER_BY_ID_ROUTE: &str = "/v0/order_book/orders/:order_id";

/// Returns the supported token list
pub const GET_SUPPORTED_TOKENS_ROUTE: &str = "/v0/supported-tokens";

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

/// The response type to fetch the supported token list
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetSupportedTokensResponse {
    /// The supported tokens
    pub tokens: Vec<ApiToken>,
}
