//! Groups price reporting API handlers and types

use async_trait::async_trait;
use external_api::http::price_report::{GetPriceReportRequest, GetPriceReportResponse};
use hyper::HeaderMap;

use crate::{
    error::{internal_error, ApiServerError},
    router::{QueryParams, TypedHandler, UrlParams},
    worker::ApiServerConfig,
};

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
