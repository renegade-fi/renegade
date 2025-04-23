//! Groups routes and handlers for order book API operations

use async_trait::async_trait;
use common::types::{token::Token, wallet::pair_from_mints};
use constants::EXTERNAL_MATCH_RELAYER_FEE;
use external_api::{
    http::order_book::{
        GetDepthByMintResponse, GetExternalMatchFeeResponse, GetNetworkOrderByIdResponse,
        GetNetworkOrdersResponse,
    },
    types::DepthSide,
    EmptyRequestResponse,
};
use hyper::HeaderMap;
use itertools::Itertools;
use job_types::price_reporter::PriceReporterQueue;
use state::State;
use util::on_chain::get_external_match_fee;

use crate::{
    error::{internal_error, not_found, ApiServerError},
    router::{QueryParams, TypedHandler, UrlParams},
};

use super::{parse_mint_from_params, parse_order_id_from_params};

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

/// Handler for the GET /order_book/external-match-fee route
#[derive(Clone)]
pub struct GetExternalMatchFeesHandler;

#[async_trait]
impl TypedHandler for GetExternalMatchFeesHandler {
    type Request = EmptyRequestResponse;
    type Response = GetExternalMatchFeeResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let asset = parse_mint_from_params(&query_params)?;
        let relayer_fee = EXTERNAL_MATCH_RELAYER_FEE;
        let protocol_fee = get_external_match_fee(&asset).to_f64();
        Ok(GetExternalMatchFeeResponse {
            protocol_fee: protocol_fee.to_string(),
            relayer_fee: relayer_fee.to_string(),
        })
    }
}

/// Handler for the GET /order_book/depth/:mint route
#[derive(Clone)]
pub struct GetDepthByMintHandler {
    /// A handle to the relayer state
    state: State,
    /// The price reporter work queue
    price_reporter_work_queue: PriceReporterQueue,
}

impl GetDepthByMintHandler {
    /// Constructor
    pub fn new(state: State, price_reporter_work_queue: PriceReporterQueue) -> Self {
        Self { state, price_reporter_work_queue }
    }
}

#[async_trait]
impl TypedHandler for GetDepthByMintHandler {
    type Request = EmptyRequestResponse;
    type Response = GetDepthByMintResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let mint = parse_mint_from_params(&params)?;
        let base_token = Token::from_addr_biguint(&mint);
        let quote_token = Token::usdc();

        // Get the price
        let ts_price = self
            .price_reporter_work_queue
            .peek_price_usdc(base_token.clone())
            .await
            .map_err(internal_error)?;

        // Get the matchable amount
        let pair = pair_from_mints(mint, quote_token.get_addr_biguint());
        let (buy_liquidity, sell_liquidity) = self.state.get_liquidity_for_pair(&pair).await;
        let buy_usd = base_token.convert_to_decimal(buy_liquidity) * ts_price.price;
        let sell_usd = base_token.convert_to_decimal(sell_liquidity) * ts_price.price;

        let buy = DepthSide { total_quantity: buy_liquidity, total_quantity_usd: buy_usd };
        let sell = DepthSide { total_quantity: sell_liquidity, total_quantity_usd: sell_usd };

        Ok(GetDepthByMintResponse {
            price: ts_price.price,
            timestamp: ts_price.timestamp,
            buy,
            sell,
        })
    }
}
