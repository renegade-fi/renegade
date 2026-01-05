//! Types for request response about order book info

use serde::{Deserialize, Serialize};
use types_account::account::IntentIdentifier;

/// The message type used to request order information from a peer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrderInfoRequest {
    /// The IDs of the orders
    pub order_ids: Vec<IntentIdentifier>,
}

/// The message type used to response with order information to a peer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrderInfoResponse {
    /// The info for the requested orders, if they were found
    pub order_info: Vec<NetworkOrderInfo>,
}

/// The sub-message type for an order's info
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkOrderInfo {
    /// The order itself
    pub order: NetworkOrder,
    /// The validity proofs for the order
    pub validity_proofs: Option<OrderValidityProofBundle>,
}
