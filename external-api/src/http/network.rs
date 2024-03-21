//! Groups API type definitions for peer-to-peer network API operations

use serde::{Deserialize, Serialize};

use crate::types::{Cluster, Network, Peer};

// ---------------
// | HTTP Routes |
// ---------------

/// Returns the full network topology known to the local node
pub const GET_NETWORK_TOPOLOGY_ROUTE: &str = "/v0/network";
/// Returns the cluster information for the specified cluster
pub const GET_CLUSTER_INFO_ROUTE: &str = "/v0/network/clusters/:cluster_id";
/// Returns the peer info for a given peer
pub const GET_PEER_INFO_ROUTE: &str = "/v0/network/peers/:peer_id";

// -------------
// | API Types |
// -------------

/// The response type to fetch the entire known network topology
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetNetworkTopologyResponse {
    /// The network topology
    pub network: Network,
}

/// The response type to fetch a cluster's info by its cluster ID
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetClusterInfoResponse {
    /// The requested cluster
    pub cluster: Cluster,
}

/// The response type to fetch a given peer's info
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetPeerInfoResponse {
    /// The requested peer
    pub peer: Peer,
}
