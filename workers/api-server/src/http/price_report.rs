//! Groups price reporting API handlers and types

use std::iter;

use async_trait::async_trait;
use common::types::token::{Token, get_all_base_tokens};
use external_api::{
    EmptyRequestResponse,
    http::price_report::{
        GetPriceReportResponse, GetSupportedTokensResponse, GetTokenPricesResponse, TokenPrice,
    },
    types::ApiToken,
};
use hyper::HeaderMap;
use itertools::Itertools;
use price_state::PriceStreamStates;

use crate::{
    error::ApiServerError,
    param_parsing::parse_token_from_params,
    router::{QueryParams, TypedHandler, UrlParams},
};

// ------------------
// | Route Handlers |
// ------------------

/// Handler for the /v0/price_report route, returns the price report for a given
/// pair
#[derive(Clone)]
pub(crate) struct PriceReportHandler {
    /// The price streams from the price reporter
    price_streams: PriceStreamStates,
}

impl PriceReportHandler {
    /// Create a new handler for "/v0/price_report"
    pub fn new(price_streams: PriceStreamStates) -> Self {
        Self { price_streams }
    }
}

#[async_trait]
impl TypedHandler for PriceReportHandler {
    type Request = EmptyRequestResponse;
    type Response = GetPriceReportResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let base = parse_token_from_params(&params)?;
        let quote = Token::usdc();
        let price_report = self.price_streams.get_state(&base, &quote);
        Ok(GetPriceReportResponse { price_report })
    }
}

/// Handler for the GET /supported-tokens route
#[derive(Clone)]
pub struct GetSupportedTokensHandler;

#[async_trait]
impl TypedHandler for GetSupportedTokensHandler {
    type Request = EmptyRequestResponse;
    type Response = GetSupportedTokensResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let tokens = get_all_base_tokens()
            .into_iter()
            .chain(iter::once(Token::usdc()))
            .map(|token| ApiToken::new(token.get_addr(), token.get_ticker().unwrap()))
            .collect_vec();

        Ok(GetSupportedTokensResponse { tokens })
    }
}

/// Handler for the /v0/token-prices route, returns prices for all supported
/// pairs
#[derive(Clone)]
pub(crate) struct TokenPricesHandler {
    /// The price streams from the price reporter
    price_streams: PriceStreamStates,
}

impl TokenPricesHandler {
    /// Create a new handler for "/v0/token-prices"
    pub fn new(price_streams: PriceStreamStates) -> Self {
        Self { price_streams }
    }
}

#[async_trait]
impl TypedHandler for TokenPricesHandler {
    type Request = EmptyRequestResponse;
    type Response = GetTokenPricesResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let usdc = Token::usdc();
        let mut token_prices = Vec::new();

        // Fetch a price for each configured base token
        for base_token in get_all_base_tokens() {
            let price = self.price_streams.peek_price(&base_token)?;
            token_prices.push(TokenPrice { base_token, quote_token: usdc.clone(), price });
        }
        Ok(GetTokenPricesResponse { token_prices })
    }
}
