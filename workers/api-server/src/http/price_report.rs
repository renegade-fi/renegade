//! Groups price reporting API handlers and types

use async_trait::async_trait;
use external_api::http::price_report::{GetPriceReportRequest, GetPriceReportResponse};
use hyper::HeaderMap;
use job_types::price_reporter::PriceReporterJob;
use tokio::sync::oneshot::channel;

use crate::{
    error::ApiServerError,
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
        let (price_reporter_state_sender, price_reporter_state_receiver) = channel();
        self.config
            .price_reporter_work_queue
            .send(PriceReporterJob::PeekPrice {
                base_token: req.base_token.clone(),
                quote_token: req.quote_token.clone(),
                channel: price_reporter_state_sender,
            })
            .unwrap();

        Ok(GetPriceReportResponse { price_report: price_reporter_state_receiver.await.unwrap() })
    }
}
