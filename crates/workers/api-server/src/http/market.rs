//! Route handlers for market operations

use async_trait::async_trait;
use external_api::{
    EmptyRequestResponse,
    http::market::{GetMarketDepthByMintResponse, GetMarketDepthsResponse, GetMarketsResponse},
};
use hyper::HeaderMap;

use crate::{
    error::ApiServerError,
    router::{QueryParams, TypedHandler, UrlParams},
};

// ------------------
// | Error Messages |
// ------------------

/// Error message for not implemented
const ERR_NOT_IMPLEMENTED: &str = "not implemented";

// --------------------
// | Market Handlers  |
// --------------------

/// Handler for GET /v2/markets
pub struct GetMarketsHandler;

impl GetMarketsHandler {
    /// Constructor
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TypedHandler for GetMarketsHandler {
    type Request = EmptyRequestResponse;
    type Response = GetMarketsResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        Err(ApiServerError::not_implemented(ERR_NOT_IMPLEMENTED))
    }
}

/// Handler for GET /v2/markets/depth
pub struct GetMarketDepthsHandler;

impl GetMarketDepthsHandler {
    /// Constructor
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TypedHandler for GetMarketDepthsHandler {
    type Request = EmptyRequestResponse;
    type Response = GetMarketDepthsResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        Err(ApiServerError::not_implemented(ERR_NOT_IMPLEMENTED))
    }
}

/// Handler for GET /v2/markets/:mint/depth
pub struct GetMarketDepthByMintHandler;

impl GetMarketDepthByMintHandler {
    /// Constructor
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TypedHandler for GetMarketDepthByMintHandler {
    type Request = EmptyRequestResponse;
    type Response = GetMarketDepthByMintResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        Err(ApiServerError::not_implemented(ERR_NOT_IMPLEMENTED))
    }
}

/// Handler for GET /v2/markets/:mint/price
/// Returns a plain text price string
pub struct GetMarketPriceHandler;

impl GetMarketPriceHandler {
    /// Constructor
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TypedHandler for GetMarketPriceHandler {
    type Request = EmptyRequestResponse;
    type Response = String;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        Err(ApiServerError::not_implemented(ERR_NOT_IMPLEMENTED))
    }
}
