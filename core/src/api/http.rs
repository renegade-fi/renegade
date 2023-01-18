//! Groups API definitions for the externally facing HTTP API

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::{
    gossip::types::WrappedPeerId,
    price_reporter::{
        exchanges::{Exchange, ExchangeConnectionState},
        reporter::PriceReporterState,
        tokens::Token,
    },
};

/// A ping request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PingRequest;

/// A ping response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PingResponse {
    /// The timestamp when the response is sent
    pub timestamp: u128,
}

/// A request to get the health of each exchange for a given token pair
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetExchangeHealthStatesRequest {
    /// The base token
    pub base_token: Token,
    /// The quote token
    pub quote_token: Token,
}

/// A response containing the health of each exchange
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetExchangeHealthStatesResponse {
    /// The PriceReporterState corresponding to the instantaneous median PriceReport
    pub median: PriceReporterState,
    /// The map of all ExchangeConnectionState corresponding to each individual exchange
    pub all_exchanges: HashMap<Exchange, ExchangeConnectionState>,
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
