//! Groups API definitions for the externally facing HTTP API

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::gossip::types::WrappedPeerId;

/// A request to get the replicas of a given wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetReplicasRequest {
    /// The ID of the wallet requested
    pub wallet_id: Uuid,
}

/// A response containing the known replicas for a given wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetReplicasResponse {
    /// The number of replicas for the wallet
    pub replicas: Vec<WrappedPeerId>,
}
