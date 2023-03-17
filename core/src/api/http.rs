//! Groups API definitions for the externally facing HTTP API

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{
    price_reporter::{
        exchanges::{Exchange, ExchangeConnectionState},
        reporter::PriceReporterState,
        tokens::Token,
    },
    state::wallet::Wallet,
};

// ------------------------------------
// | Generic Request Response Formats |
// ------------------------------------

/// A ping response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PingResponse {
    /// The timestamp when the response is sent
    pub timestamp: u128,
}

// ----------------------------------------------
// | Wallet Operations Request Response Formats |
// ----------------------------------------------

/// The response type to get a wallet's information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetWalletResponse {
    /// The wallet requested by the client
    pub wallet: Wallet,
}

// --------------------------------------------
// | Price Reporting Request Response Formats |
// --------------------------------------------

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
