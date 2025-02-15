//! Groups API types for order book API operations

use serde::{Deserialize, Serialize};

use crate::types::ApiNetworkOrder;

// ---------------
// | HTTP Routes |
// ---------------

/// Returns all known network orders
pub const GET_NETWORK_ORDERS_ROUTE: &str = "/v0/order_book/orders";
/// Returns the network order information of the specified order
pub const GET_NETWORK_ORDER_BY_ID_ROUTE: &str = "/v0/order_book/orders/:order_id";
/// Returns the external match fee for a given asset
pub const GET_EXTERNAL_MATCH_FEE_ROUTE: &str = "/v0/order_book/external-match-fee";

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
