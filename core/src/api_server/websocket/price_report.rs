//! Handlers for price reporting websocket topics

use hyper::StatusCode;
use async_trait::async_trait;
use tokio::sync::mpsc::UnboundedSender as TokioSender;
use tokio::sync::oneshot::channel;

use crate::{
    api_server::{error::ApiServerError, router::UrlParams},
    price_reporter::{jobs::PriceReporterManagerJob, price_report_topic_name, tokens::Token},
    system_bus::{SystemBus, TopicReader},
    types::SystemBusMessage,
};

use super::handler::WebsocketTopicHandler;

// ------------------
// | Error Messages |
// ------------------

/// The error emitted when a route is missing parameters
const ERR_MISSING_PARAMS: &str = "route missing parameters";
/// The error message given when communication with the price reporter fails
const ERR_SENDING_MESSAGE: &str = "error sending message to price reporter";

// ----------------
// | URL Captures |
// ----------------

/// The source to fetch a price report from
const PRICE_SOURCE_URL_PARAM: &str = "source";
/// The base mint url param to fetch a price report for
const BASE_MINT_URL_PARAM: &str = "base";
/// The quote mint url param to fetch a price report for
const QUOTE_MINT_URL_PARAM: &str = "quote";

/// Parse a price report source from a set of URL params
fn parse_source_from_url_params(params: &UrlParams) -> Result<String, ApiServerError> {
    params
        .get(&PRICE_SOURCE_URL_PARAM.to_string())
        .ok_or_else(|| {
            ApiServerError::HttpStatusCode(StatusCode::BAD_REQUEST, ERR_MISSING_PARAMS.to_string())
        })
        .cloned()
}

/// Parse a base mint from a URL param
fn parse_base_mint_from_url_params(params: &UrlParams) -> Result<String, ApiServerError> {
    params
        .get(&BASE_MINT_URL_PARAM.to_string())
        .ok_or_else(|| {
            ApiServerError::HttpStatusCode(StatusCode::BAD_REQUEST, ERR_MISSING_PARAMS.to_string())
        })
        .cloned()
}

/// Parse a quote mint from a URL param
fn parse_quote_mint_from_url_params(params: &UrlParams) -> Result<String, ApiServerError> {
    params
        .get(&QUOTE_MINT_URL_PARAM.to_string())
        .ok_or_else(|| {
            ApiServerError::HttpStatusCode(StatusCode::BAD_REQUEST, ERR_MISSING_PARAMS.to_string())
        })
        .cloned()
}

// -----------
// | Handler |
// -----------

/// The handler that manages a subscription to a price report
#[derive(Clone)]
pub struct PriceReporterHandler {
    /// A sender to the price reporter's work queue
    price_reporter_work_queue: TokioSender<PriceReporterManagerJob>,
    /// A reference to the relayer-global system bus    
    system_bus: SystemBus<SystemBusMessage>,
}

impl PriceReporterHandler {
    /// Constructor
    pub fn new(
        price_reporter_work_queue: TokioSender<PriceReporterManagerJob>,
        system_bus: SystemBus<SystemBusMessage>,
    ) -> Self {
        Self {
            price_reporter_work_queue,
            system_bus,
        }
    }
}

#[async_trait]
impl WebsocketTopicHandler for PriceReporterHandler {
    /// Handle a subscription to a price report
    ///
    /// Send a message to the price reporter indicating that it should
    /// open websockets to the reporting exchanges
    async fn handle_subscribe_message(
        &self,
        _topic: String,
        route_params: &UrlParams,
    ) -> Result<TopicReader<SystemBusMessage>, ApiServerError> {
        // Parse the source, base mint, and quote mint from the route
        let source = parse_source_from_url_params(route_params)?;
        let base = Token::from_addr(&parse_base_mint_from_url_params(route_params)?);
        let quote = Token::from_addr(&parse_quote_mint_from_url_params(route_params)?);

        // Start a price reporting stream in the manager
        let (channel, _) = channel();
        self.price_reporter_work_queue
            .send(PriceReporterManagerJob::StartPriceReporter {
                base_token: base.clone(),
                quote_token: quote.clone(),
                id: None,
                channel, /* unused here */
            })
            .map_err(|_| ApiServerError::WebsocketServerFailure(ERR_SENDING_MESSAGE.to_string()))?;

        Ok(self
            .system_bus
            .subscribe(price_report_topic_name(&source, base, quote)))
    }

    /// Handle an unsubscribe message from the price reporter
    ///
    /// TODO: Cleanup unused websocket connections after this happens
    /// for now, this does nothing
    async fn handle_unsubscribe_message(
        &self,
        _topic: String,
        _route_params: &UrlParams,
    ) -> Result<(), ApiServerError> {
        Ok(())
    }
}
