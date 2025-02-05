//! Groups routes and handlers for order book API operations

use async_trait::async_trait;
use common::types::token::{read_token_remap, USDT_TICKER, USD_TICKER};
use external_api::{
    http::{
        order_book::{GetNetworkOrderByIdResponse, GetNetworkOrdersResponse},
        GetSupportedTokensResponse,
    },
    types::ApiToken,
    EmptyRequestResponse,
};
use hyper::HeaderMap;
use itertools::Itertools;
use state::State;

use crate::{
    error::{not_found, ApiServerError},
    router::{QueryParams, TypedHandler, UrlParams},
};

use super::parse_order_id_from_params;

/// Tokens filtered from the supported token endpoint
const FILTERED_TOKENS: [&str; 2] = [USD_TICKER, USDT_TICKER];

// ------------------
// | Error Messages |
// ------------------

/// Error displayed when an order cannot be found in the network order book
const ERR_ORDER_NOT_FOUND: &str = "order not found in network order book";

// ----------------------
// | Order Book Routers |
// ----------------------

/// Handler for the GET /order_book/orders route
#[derive(Clone)]
pub struct GetNetworkOrdersHandler {
    /// A copy of the relayer-global state
    pub state: State,
}

impl GetNetworkOrdersHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for GetNetworkOrdersHandler {
    type Request = EmptyRequestResponse;
    type Response = GetNetworkOrdersResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        // Fetch all orders from state and convert to api type
        let all_orders = self.state.get_all_orders().await?;
        let orders = all_orders.into_iter().map(Into::into).collect_vec();

        Ok(GetNetworkOrdersResponse { orders })
    }
}

/// Handler for the GET /order_book/orders route
#[derive(Clone)]
pub struct GetNetworkOrderByIdHandler {
    /// A copy of the relayer-global state
    pub state: State,
}

impl GetNetworkOrderByIdHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for GetNetworkOrderByIdHandler {
    type Request = EmptyRequestResponse;
    type Response = GetNetworkOrderByIdResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let order_id = parse_order_id_from_params(&params)?;
        if let Some(order) = self.state.get_order(&order_id).await? {
            Ok(GetNetworkOrderByIdResponse { order: order.into() })
        } else {
            Err(not_found(ERR_ORDER_NOT_FOUND.to_string()))
        }
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
        let token_map = read_token_remap();
        let tokens = token_map
            .iter()
            .map(|(addr, sym)| ApiToken::new(addr.clone(), sym.clone()))
            .filter(|token| !FILTERED_TOKENS.contains(&token.symbol.as_str()))
            .collect_vec();

        Ok(GetSupportedTokensResponse { tokens })
    }
}
