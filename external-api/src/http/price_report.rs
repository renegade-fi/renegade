//! Groups price reporting API types

use std::collections::HashMap;

use common::types::{
    exchange::{Exchange, ExchangeConnectionState, PriceReporterState},
    token::Token,
};
use serde::{Deserialize, Serialize};

// ---------------
// | HTTP Routes |
// ---------------

/// Exchange health check route
pub const EXCHANGE_HEALTH_ROUTE: &str = "/v0/exchange/health_check";

// -------------
// | API Types |
// -------------

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
    /// The PriceReporterState corresponding to the instantaneous median
    /// PriceReport
    pub median: PriceReporterState,
    /// The map of all ExchangeConnectionState corresponding to each individual
    /// exchange
    pub all_exchanges: HashMap<Exchange, ExchangeConnectionState>,
}
