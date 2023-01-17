//! Groups API definitions for the externally facing HTTP API

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::gossip::types::WrappedPeerId;

/// A ping request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PingRequest;

/// A ping response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PingResponse {
    /// The timestamp when the response is sent
    pub timestamp: u128,
}

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
