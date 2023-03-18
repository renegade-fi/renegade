//! Groups price reporting API handlers and types

use async_trait::async_trait;
use crossbeam::channel;

use crate::{
    api_server::{
        error::ApiServerError,
        router::{TypedHandler, UrlParams},
        worker::ApiServerConfig,
    },
    external_api::http::price_report::{
        GetExchangeHealthStatesRequest, GetExchangeHealthStatesResponse,
    },
    price_reporter::jobs::PriceReporterManagerJob,
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
#[derive(Clone, Debug)]
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
        req: Self::Request,
        _params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        let (price_reporter_state_sender, price_reporter_state_receiver) = channel::unbounded();
        self.config
            .price_reporter_work_queue
            .send(PriceReporterManagerJob::PeekMedian {
                base_token: req.base_token.clone(),
                quote_token: req.quote_token.clone(),
                channel: price_reporter_state_sender,
            })
            .unwrap();
        let (exchange_connection_state_sender, exchange_connection_state_receiver) =
            channel::unbounded();
        self.config
            .price_reporter_work_queue
            .send(PriceReporterManagerJob::PeekAllExchanges {
                base_token: req.base_token,
                quote_token: req.quote_token,
                channel: exchange_connection_state_sender,
            })
            .unwrap();
        Ok(GetExchangeHealthStatesResponse {
            median: price_reporter_state_receiver.recv().unwrap(),
            all_exchanges: exchange_connection_state_receiver.recv().unwrap(),
        })
    }
}
