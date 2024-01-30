//! Groups price reporting API handlers and types

use async_trait::async_trait;
use external_api::http::price_report::{
    GetExchangeHealthStatesRequest, GetExchangeHealthStatesResponse,
};
use hyper::HeaderMap;
use job_types::price_reporter::PriceReporterJob;
use tokio::sync::oneshot::channel;

use crate::{
    error::ApiServerError,
    router::{TypedHandler, UrlParams},
    worker::ApiServerConfig,
};

// ---------------
// | HTTP Routes |
// ---------------

/// Exchange health check route
pub(super) const EXCHANGE_HEALTH_ROUTE: &str = "/v0/exchange/health_check";

// ------------------
// | Route Handlers |
// ------------------

/// Handler for the / route, returns the health report for each individual
/// exchange and the aggregate median
#[derive(Clone)]
pub(crate) struct ExchangeHealthStatesHandler {
    /// The config for the API server
    config: ApiServerConfig,
}

impl ExchangeHealthStatesHandler {
    /// Create a new handler for "/exchange/health"
    pub fn new(config: ApiServerConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl TypedHandler for ExchangeHealthStatesHandler {
    type Request = GetExchangeHealthStatesRequest;
    type Response = GetExchangeHealthStatesResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        req: Self::Request,
        _params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        let (price_reporter_state_sender, price_reporter_state_receiver) = channel();
        self.config
            .price_reporter_work_queue
            .send(PriceReporterJob::PeekMedian {
                base_token: req.base_token.clone(),
                quote_token: req.quote_token.clone(),
                channel: price_reporter_state_sender,
            })
            .unwrap();
        let (exchange_connection_state_sender, exchange_connection_state_receiver) = channel();
        self.config
            .price_reporter_work_queue
            .send(PriceReporterJob::PeekAllExchanges {
                base_token: req.base_token,
                quote_token: req.quote_token,
                channel: exchange_connection_state_sender,
            })
            .unwrap();
        Ok(GetExchangeHealthStatesResponse {
            median: price_reporter_state_receiver.await.unwrap(),
            all_exchanges: exchange_connection_state_receiver.await.unwrap(),
        })
    }
}
