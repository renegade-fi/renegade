//! Groups API type definitions for peer-to-peer network API operations

use serde::{Deserialize, Serialize};

use crate::external_api::types::Network;

/// The response type to fetch the entire known network topology
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetNetworkTopologyResponse {
    /// The network topology
    pub network: Network,
}
