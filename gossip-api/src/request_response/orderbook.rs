//! Types for request response about order book info

use common::types::{network_order::NetworkOrder, wallet::OrderIdentifier};
use serde::{Deserialize, Serialize};

/// The message type used to request order information from a peer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrderInfoRequest {
    /// The ID of the order
    pub order_id: OrderIdentifier,
}

/// The message type used to response with order information to a peer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrderInfoResponse {
    /// The ID of the order that the info is attached to
    pub order_id: OrderIdentifier,
    /// The order information stored locally for the order
    ///
    /// Value is `None` if the local peer does not store the order
    pub info: Option<NetworkOrder>,
}
