//! API types for order book requests

use common::types::network_order::{NetworkOrder, NetworkOrderState};
use num_bigint::BigUint;
use renegade_crypto::fields::scalar_to_biguint;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The order book known to the local node, consisting of all opaque
/// network orders being shopped around by peers
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrderBook {
    /// The list of known orders
    pub orders: Vec<ApiNetworkOrder>,
}

/// An opaque order known to the local peer only by a few opaque identifiers
/// possibly owned and known in the clear by the local peer as well
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiNetworkOrder {
    /// Identifier
    pub id: Uuid,
    /// The nullifier of the containing wallet's public secret shares
    pub public_share_nullifier: BigUint,
    /// Whether this order is managed by the local cluster
    pub local: bool,
    /// The cluster that manages this order
    pub cluster: String,
    /// The state of the order in the network
    pub state: NetworkOrderState,
    /// The timestamp that this order was first received at
    pub timestamp: u64,
}

impl From<NetworkOrder> for ApiNetworkOrder {
    fn from(order: NetworkOrder) -> Self {
        ApiNetworkOrder {
            id: order.id,
            public_share_nullifier: scalar_to_biguint(&order.public_share_nullifier),
            local: order.local,
            cluster: order.cluster.to_string(),
            state: order.state,
            timestamp: order.timestamp,
        }
    }
}
