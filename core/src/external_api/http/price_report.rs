//! Groups price reporting API types

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::price_reporter::{
    exchange::{Exchange, ExchangeConnectionState},
    reporter::PriceReporterState,
    tokens::Token,
};

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
