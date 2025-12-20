//! Groups price reporting API types

use common::types::{exchange::PriceReporterState, price::Price, token::Token};
use serde::{Deserialize, Serialize};

use crate::{
    deserialize_token_from_hex_string, f64_string_serde, serialize_token_as_hex_string,
    types::ApiToken,
};

// ---------------
// | HTTP Routes |
// ---------------

/// Price report route
pub const PRICE_REPORT_ROUTE: &str = "/v0/price_report/:mint";
/// Returns the supported token list
pub const GET_SUPPORTED_TOKENS_ROUTE: &str = "/v0/supported-tokens";
/// Returns the prices for all supported pairs
pub const GET_TOKEN_PRICES_ROUTE: &str = "/v0/token-prices";

/// A response containing the relayer's price report for a pair
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetPriceReportResponse {
    /// The PriceReporterState corresponding to the pair
    pub price_report: PriceReporterState,
}

/// The response type to fetch the supported token list
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetSupportedTokensResponse {
    /// The supported tokens
    pub tokens: Vec<ApiToken>,
}

/// A response containing all token prices
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetTokenPricesResponse {
    /// List of tokens with their price information
    pub token_prices: Vec<TokenPrice>,
}

/// Price information for a token
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenPrice {
    /// The base token
    #[serde(
        serialize_with = "serialize_token_as_hex_string",
        deserialize_with = "deserialize_token_from_hex_string"
    )]
    pub base_token: Token,
    /// The quote token
    #[serde(
        serialize_with = "serialize_token_as_hex_string",
        deserialize_with = "deserialize_token_from_hex_string"
    )]
    pub quote_token: Token,
    /// The price data for this token
    #[serde(with = "f64_string_serde")]
    pub price: Price,
}
