//! Types for request response about order book info

use common::types::{network_order::NetworkOrder, wallet::OrderIdentifier};
use serde::{Deserialize, Serialize};

/// The message type used to request order information from a peer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrderInfoRequest {
    /// The IDs of the orders
    pub order_ids: Vec<OrderIdentifier>,
}

/// The message type used to response with order information to a peer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrderInfoResponse {
    /// The info for the requested orders, if they were found
    pub order_info: Vec<NetworkOrder>,
}
