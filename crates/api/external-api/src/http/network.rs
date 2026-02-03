//! Groups API type definitions for network API operations

use serde::{Deserialize, Serialize};

use crate::types::Network;

// ---------------
// | HTTP Routes |
// ---------------

/// Returns the full network topology known to the local node
pub const GET_NETWORK_TOPOLOGY_ROUTE: &str = "/v2/network";

// -------------
// | API Types |
// -------------

/// The response type to fetch the entire known network topology
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetNetworkTopologyResponse {
    /// The local peer's cluster ID
    pub local_cluster_id: String,
    /// The network topology
    pub network: Network,
}
