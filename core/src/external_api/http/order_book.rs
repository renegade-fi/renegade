//! Groups API types for order book API operations

use serde::{Deserialize, Serialize};

use crate::external_api::types::NetworkOrder;

/// The response type to fetch all the known orders in the network
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetNetworkOrdersResponse {
    /// The orders known to the local peer
    pub orders: Vec<NetworkOrder>,
}
