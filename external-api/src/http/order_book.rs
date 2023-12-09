//! Groups API types for order book API operations

use serde::{Deserialize, Serialize};

use crate::types::ApiNetworkOrder;

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
