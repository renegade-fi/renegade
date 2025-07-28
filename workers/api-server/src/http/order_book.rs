//! Groups routes and handlers for order book API operations

use async_trait::async_trait;
use common::types::{
    token::{Token, get_all_base_tokens},
    wallet::pair_from_mints,
};
use constants::DEFAULT_EXTERNAL_MATCH_RELAYER_FEE;
use external_api::{
    EmptyRequestResponse,
    http::order_book::{
        GetDepthByMintResponse, GetDepthForAllPairsResponse, GetExternalMatchFeeResponse,
        GetNetworkOrderByIdResponse, GetNetworkOrdersResponse, PriceAndDepth,
    },
    types::DepthSide,
};
use hyper::HeaderMap;
use itertools::Itertools;
use job_types::price_reporter::PriceReporterQueue;
use num_traits::ToPrimitive;
use state::State;
use util::on_chain::get_external_match_fee;

use crate::{
    error::{ApiServerError, internal_error, not_found},
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

// ---------------
// | Fees Routes |
// ---------------

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
        let relayer_fee = DEFAULT_EXTERNAL_MATCH_RELAYER_FEE;
        let protocol_fee = get_external_match_fee(&asset).to_f64();
        Ok(GetExternalMatchFeeResponse {
            protocol_fee: protocol_fee.to_string(),
            relayer_fee: relayer_fee.to_string(),
        })
    }
}

// ---------------------------
// | Order Book Depth Routes |
// ---------------------------

/// A helper struct encapsulating common logic between depth routes
#[derive(Clone)]
struct DepthCalculator {
    /// A handle to the relayer state
    state: State,
    /// The price reporter work queue
    price_reporter_work_queue: PriceReporterQueue,
}

impl DepthCalculator {
    /// Constructor
    pub fn new(state: State, price_reporter_work_queue: PriceReporterQueue) -> Self {
        Self { state, price_reporter_work_queue }
    }

    /// Get the price and depth information for a single token
    async fn get_price_and_depth(&self, token: Token) -> Result<PriceAndDepth, ApiServerError> {
        let quote_token = Token::usdc();

        // Get the price
        let ts_price = self
            .price_reporter_work_queue
            .peek_price_usdc(token.clone())
            .await
            .map_err(internal_error)?;

        // Get the matchable amount
        let pair = pair_from_mints(token.get_addr_biguint(), quote_token.get_addr_biguint());
        let (buy_liquidity_quote, sell_liquidity) = self.state.get_liquidity_for_pair(&pair).await;

        let buy_usd = quote_token.convert_to_decimal(buy_liquidity_quote);
        let sell_usd = token.convert_to_decimal(sell_liquidity) * ts_price.price;

        // Convert buy_liquidity (in terms of quote token) to be in terms of the base
        let base_decimals = token.get_decimals().unwrap();
        let buy_liquidity_base_decimal = buy_usd / ts_price.price;
        let buy_liquidity_base = buy_liquidity_base_decimal * 10f64.powi(base_decimals as i32);
        let buy_liquidity_base: u128 = buy_liquidity_base.to_u128().unwrap();

        let buy = DepthSide { total_quantity: buy_liquidity_base, total_quantity_usd: buy_usd };
        let sell = DepthSide { total_quantity: sell_liquidity, total_quantity_usd: sell_usd };
        let address = token.get_addr();

        Ok(PriceAndDepth {
            address,
            price: ts_price.price,
            timestamp: ts_price.timestamp,
            buy,
            sell,
        })
    }
}

/// Handler for the GET /order_book/depth/:mint route
#[derive(Clone)]
pub struct GetDepthByMintHandler {
    /// The depth calculator for fetching price and depth data
    depth_calculator: DepthCalculator,
}

impl GetDepthByMintHandler {
    /// Constructor
    pub fn new(state: State, price_reporter_work_queue: PriceReporterQueue) -> Self {
        let depth_calculator = DepthCalculator::new(state, price_reporter_work_queue);
        Self { depth_calculator }
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
        let depth = self.depth_calculator.get_price_and_depth(base_token).await?;
        Ok(GetDepthByMintResponse { depth })
    }
}

/// Handler for the GET /order_book/depth route
#[derive(Clone)]
pub struct GetDepthForAllPairsHandler {
    /// The depth calculator for fetching price and depth data
    depth_calculator: DepthCalculator,
}

impl GetDepthForAllPairsHandler {
    /// Constructor
    pub fn new(state: State, price_reporter_work_queue: PriceReporterQueue) -> Self {
        let depth_calculator = DepthCalculator::new(state, price_reporter_work_queue);
        Self { depth_calculator }
    }
}

#[async_trait]
impl TypedHandler for GetDepthForAllPairsHandler {
    type Request = EmptyRequestResponse;
    type Response = GetDepthForAllPairsResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        // Get all tokens for which we support price data
        // Practically, this is all non-stablecoin tokens
        let supported_tokens = get_all_base_tokens();
        let quote_token = Token::usdc();

        let mut pairs = Vec::new();
        for token in supported_tokens {
            // Skip USDC since we don't need USDC/USDC pair
            if token == quote_token {
                continue;
            }

            // Get the price and depth for this token, skip if error
            match self.depth_calculator.get_price_and_depth(token).await {
                Ok(price_and_depth) => pairs.push(price_and_depth),
                Err(_) => continue, // Skip tokens without price data or other errors
            }
        }

        Ok(GetDepthForAllPairsResponse { pairs })
    }
}
