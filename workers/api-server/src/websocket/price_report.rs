//! Handlers for price reporting websocket topics

use async_trait::async_trait;
use common::types::token::Token;
use external_api::bus_message::{SystemBusMessage, price_report_topic};
use system_bus::{SystemBus, TopicReader};

use crate::{
    auth::AuthType,
    error::{ApiServerError, bad_request},
    router::UrlParams,
};

use super::handler::WebsocketTopicHandler;

// ------------------
// | Error Messages |
// ------------------

/// The error emitted when a route is missing parameters
const ERR_MISSING_PARAMS: &str = "route missing parameters";
/// The error message given when a pair is invalid
const ERR_INVALID_PAIR: &str = "invalid pair";

// ----------------
// | URL Captures |
// ----------------

/// The base mint url param to fetch a price report for
const BASE_MINT_URL_PARAM: &str = "base";
/// The quote mint url param to fetch a price report for
const QUOTE_MINT_URL_PARAM: &str = "quote";

/// Parse a base mint from a URL param
fn parse_base_mint_from_url_params(params: &UrlParams) -> Result<String, ApiServerError> {
    params
        .get(&BASE_MINT_URL_PARAM.to_string())
        .ok_or_else(|| bad_request(ERR_MISSING_PARAMS.to_string()))
        .cloned()
}

/// Parse a quote mint from a URL param
fn parse_quote_mint_from_url_params(params: &UrlParams) -> Result<String, ApiServerError> {
    params
        .get(&QUOTE_MINT_URL_PARAM.to_string())
        .ok_or_else(|| bad_request(ERR_MISSING_PARAMS.to_string()))
        .cloned()
}

// -----------
// | Handler |
// -----------

/// The handler that manages a subscription to a price report
#[derive(Clone)]
pub struct PriceReporterHandler {
    /// A reference to the relayer-global system bus    
    system_bus: SystemBus<SystemBusMessage>,
}

impl PriceReporterHandler {
    /// Constructor
    pub fn new(system_bus: SystemBus<SystemBusMessage>) -> Self {
        Self { system_bus }
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
        // Parse the base mint and quote mint from the route
        let base = Token::from_addr(&parse_base_mint_from_url_params(route_params)?);
        let quote = Token::from_addr(&parse_quote_mint_from_url_params(route_params)?);
        let valid = base.is_named() && quote == Token::usdc();
        if !valid {
            return Err(bad_request(ERR_INVALID_PAIR.to_string()));
        }

        Ok(self.system_bus.subscribe(price_report_topic(&base, &quote)))
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

    fn auth_type(&self) -> AuthType {
        AuthType::None
    }
}
