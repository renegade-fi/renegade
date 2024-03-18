//! Groups price reporting API types

use common::types::{exchange::PriceReporterState, token::Token};
use serde::{Deserialize, Serialize};

/// A request to get the relayer's price report for a pair
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetPriceReportRequest {
    /// The base token
    pub base_token: Token,
    /// The quote token
    pub quote_token: Token,
}

/// A response containing the relayer's price report for a pair
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetPriceReportResponse {
    /// The PriceReporterState corresponding to the pair
    pub price_report: PriceReporterState,
}
