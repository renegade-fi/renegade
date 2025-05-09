//! Groups price reporting API handlers and types

use async_trait::async_trait;
use common::types::token::{get_all_tokens, Token, USDC_TICKER, USDT_TICKER, USD_TICKER};
use external_api::{
    http::price_report::{
        GetPriceReportRequest, GetPriceReportResponse, GetSupportedTokensResponse,
        GetTokenPricesResponse, TokenPrice,
    },
    types::ApiToken,
    EmptyRequestResponse,
};
use futures::{future::join_all, FutureExt};
use hyper::HeaderMap;
use itertools::Itertools;
use job_types::price_reporter::PriceReporterQueue;

use crate::{
    error::{internal_error, ApiServerError},
    router::{QueryParams, TypedHandler, UrlParams},
    worker::ApiServerConfig,
};

/// Tokens filtered from the supported token endpoint
const FILTERED_TOKENS: [&str; 2] = [USD_TICKER, USDT_TICKER];
/// Tokens filtered from the token prices endpoint
const FILTERED_TOKENS_PRICES: [&str; 3] = [USD_TICKER, USDT_TICKER, USDC_TICKER];

// ------------------
// | Route Handlers |
// ------------------

/// Handler for the /v0/price_report route, returns the price report for a given
/// pair
#[derive(Clone)]
pub(crate) struct PriceReportHandler {
    /// The config for the API server
    config: ApiServerConfig,
}

impl PriceReportHandler {
    /// Create a new handler for "/v0/price_report"
    pub fn new(config: ApiServerConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl TypedHandler for PriceReportHandler {
    type Request = GetPriceReportRequest;
    type Response = GetPriceReportResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let price_report = self
            .config
            .price_reporter_work_queue
            .peek_price_report(req.base_token.clone(), req.quote_token.clone())
            .await
            .map_err(internal_error)?;

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
        let tokens = get_all_tokens_filtered(&FILTERED_TOKENS)
            .into_iter()
            .map(|token| ApiToken::new(token.get_addr(), token.get_ticker().unwrap()))
            .collect_vec();
        Ok(GetSupportedTokensResponse { tokens })
    }
}

/// Handler for the /v0/token-prices route, returns prices for all supported
/// pairs
#[derive(Clone)]
pub(crate) struct TokenPricesHandler {
    /// The price reporter work queue
    price_reporter_work_queue: PriceReporterQueue,
}

impl TokenPricesHandler {
    /// Create a new handler for "/v0/token-prices"
    pub fn new(price_reporter_work_queue: PriceReporterQueue) -> Self {
        Self { price_reporter_work_queue }
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
        // Fetch all prices concurrently
        let usdc = Token::usdc();
        let mut price_futures = Vec::new();
        for base_token in get_all_tokens_filtered(&FILTERED_TOKENS_PRICES) {
            let job = self
                .price_reporter_work_queue
                .peek_price_usdc(base_token.clone())
                .map(|p| Ok(TokenPrice { base_token, quote_token: usdc.clone(), price: p?.price }));
            price_futures.push(job);
        }

        let token_prices = join_all(price_futures)
            .await
            .into_iter()
            .filter_map(|r: Result<TokenPrice, String>| r.ok())
            .collect_vec();
        Ok(GetTokenPricesResponse { token_prices })
    }
}

// -----------
// | Helpers |
// -----------

/// Get all tokens from the token map filtering out given tokens
fn get_all_tokens_filtered(filtered_tokens: &[&str]) -> Vec<Token> {
    get_all_tokens()
        .into_iter()
        .filter(|t| !filtered_tokens.contains(&t.get_ticker().unwrap().as_str()))
        .collect_vec()
}
