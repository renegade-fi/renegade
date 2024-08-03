//! Route handlers for the admin API

// ------------------------
// | Admin Route Handlers |
// ------------------------

use async_trait::async_trait;
use circuit_types::{fixed_point::FixedPoint, Amount};
use common::types::{
    exchange::PriceReporterState, token::Token, wallet::order_metadata::OrderMetadata, Price,
};
use external_api::{
    http::{
        admin::{
            AdminOrderMetadataResponse, CreateOrderInMatchingPoolRequest, IsLeaderResponse,
            OpenOrder, OpenOrdersResponse,
        },
        wallet::CreateOrderResponse,
    },
    EmptyRequestResponse,
};
use hyper::HeaderMap;
use job_types::{
    handshake_manager::{HandshakeExecutionJob, HandshakeManagerQueue},
    price_reporter::{PriceReporterJob, PriceReporterQueue},
};
use state::State;
use tokio::sync::oneshot;
use util::matching_engine::compute_max_amount;

use crate::{
    error::{bad_request, internal_error, not_found, ApiServerError},
    router::{QueryParams, TypedHandler, UrlParams, ERR_WALLET_NOT_FOUND},
};

use super::{
    parse_matching_pool_from_query_params, parse_matching_pool_from_url_params,
    parse_order_id_from_params, parse_wallet_id_from_params,
    wallet::{create_order, ERR_ORDER_NOT_FOUND},
};

// -------------
// | Constants |
// -------------

/// Query parameter indicating whether or not to calculate fillable values for
/// open orders
const INCLUDE_FILLABLE_PARAM: &str = "include_fillable";

/// The matching pool already exists
const ERR_MATCHING_POOL_EXISTS: &str = "matching pool already exists";
/// The matching pool for the order does not exist
const ERR_NO_MATCHING_POOL: &str = "matching pool does not exist";
/// The order already exists
const ERR_ORDER_ALREADY_EXISTS: &str = "order id already exists";
/// The balance for an order does not exist in its wallet
const ERR_BALANCE_NOT_FOUND: &str = "balance not found in wallet";
/// Error message emitted when price data cannot be found for a token pair
const ERR_NO_PRICE_DATA: &str = "no price data found for token pair";

// ------------------
// | Route Handlers |
// ------------------

// --------------
// | /is-leader |
// --------------

/// Handler for the GET /v0/admin/is-leader route
pub struct IsLeaderHandler {
    /// A handle to the relayer state
    state: State,
}

impl IsLeaderHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for IsLeaderHandler {
    type Request = EmptyRequestResponse;
    type Response = IsLeaderResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let leader = self.state.is_leader();
        Ok(IsLeaderResponse { leader })
    }
}

// ----------------
// | /open-orders |
// ----------------

/// Handler for the GET /v0/admin/open-orders route
pub struct AdminOpenOrdersHandler {
    /// A handle to the relayer state
    state: State,
    /// A handle to the price reporter's job queue
    price_reporter_job_queue: PriceReporterQueue,
}

impl AdminOpenOrdersHandler {
    /// Constructor
    pub fn new(state: State, price_reporter_job_queue: PriceReporterQueue) -> Self {
        Self { state, price_reporter_job_queue }
    }
}

#[async_trait]
impl TypedHandler for AdminOpenOrdersHandler {
    type Request = EmptyRequestResponse;
    type Response = OpenOrdersResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let order_ids =
            if let Some(matching_pool) = parse_matching_pool_from_query_params(&query_params) {
                // Check that the matching pool exists
                if !self.state.matching_pool_exists(matching_pool.clone()).await? {
                    return Err(not_found(ERR_NO_MATCHING_POOL));
                }

                self.state.get_locally_matchable_orders_in_matching_pool(matching_pool).await?
            } else {
                self.state.get_locally_matchable_orders().await?
            };

        let include_fillable = parse_include_fillable_from_query_params(&query_params)?;
        let mut orders = Vec::new();
        for id in order_ids.into_iter() {
            let order = self.state.get_order_metadata(&id).await?;
            if let Some(meta) = order {
                let (fillable, price) = if include_fillable {
                    get_fillable_amount_and_price(
                        &meta,
                        &self.state,
                        &self.price_reporter_job_queue,
                    )
                    .await
                    .map(|(fillable, price)| (Some(fillable), Some(price)))?
                } else {
                    (None, None)
                };
                orders.push(OpenOrder { order: meta, fillable, price })
            }
        }

        Ok(OpenOrdersResponse { orders })
    }
}

// ------------------------
// | /orders/:id/metadata |
// ------------------------

/// Handle for the GET /v0/admin/orders/:id/metadata route
pub struct AdminOrderMetadataHandler {
    /// A handle to the relayer state
    state: State,
}

impl AdminOrderMetadataHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for AdminOrderMetadataHandler {
    type Request = EmptyRequestResponse;
    type Response = AdminOrderMetadataResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let order_id = parse_order_id_from_params(&params)?;
        let order = self
            .state
            .get_order_metadata(&order_id)
            .await?
            .ok_or(not_found(ERR_ORDER_NOT_FOUND))?;

        Ok(AdminOrderMetadataResponse { order })
    }
}

// ----------------------------------
// | /matching_pools/:matching_pool |
// ----------------------------------

/// Handler for the POST /v0/admin/matching_pools/:matching_pool route
pub struct AdminCreateMatchingPoolHandler {
    /// A handle to the relayer state
    state: State,
}

impl AdminCreateMatchingPoolHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for AdminCreateMatchingPoolHandler {
    type Request = EmptyRequestResponse;
    type Response = EmptyRequestResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let matching_pool = parse_matching_pool_from_url_params(&params)?;

        // Check that the matching pool does not already exist
        if self.state.matching_pool_exists(matching_pool.clone()).await? {
            return Err(bad_request(ERR_MATCHING_POOL_EXISTS));
        }

        let waiter = self.state.create_matching_pool(matching_pool).await?;

        waiter.await?;
        Ok(EmptyRequestResponse {})
    }
}

// ------------------------------------------
// | /matching_pools/:matching_pool/destroy |
// ------------------------------------------

/// Handler for the POST /v0/admin/matching_pools/:matching_pool/destroy route
pub struct AdminDestroyMatchingPoolHandler {
    /// A handle to the relayer state
    state: State,
}

impl AdminDestroyMatchingPoolHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for AdminDestroyMatchingPoolHandler {
    type Request = EmptyRequestResponse;
    type Response = EmptyRequestResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let matching_pool = parse_matching_pool_from_url_params(&params)?;

        let waiter = self.state.destroy_matching_pool(matching_pool).await?;

        waiter.await?;
        Ok(EmptyRequestResponse {})
    }
}

// -----------------------------
// | /wallet/:id/order-in-pool |
// -----------------------------

/// Handler for the POST /v0/admin/wallet/:id/order-in-pool route
pub struct AdminCreateOrderInMatchingPoolHandler {
    /// A handle to the relayer state
    state: State,
}

impl AdminCreateOrderInMatchingPoolHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for AdminCreateOrderInMatchingPoolHandler {
    type Request = CreateOrderInMatchingPoolRequest;
    type Response = CreateOrderResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let matching_pool = req.matching_pool;

        // Check that the matching pool exists
        if !self.state.matching_pool_exists(matching_pool.clone()).await? {
            return Err(not_found(ERR_NO_MATCHING_POOL));
        }

        // Check that an order with the given ID does not exist
        let oid = req.order.id;
        if self.state.contains_order(&oid).await? {
            return Err(bad_request(ERR_ORDER_ALREADY_EXISTS));
        }

        create_order(req.order, req.statement_sig, wallet_id, &self.state, Some(matching_pool))
            .await
    }
}

// -----------------------------------------------------
// | /wallet/:id/orders/:id/assign-pool/:matching_pool |
// -----------------------------------------------------

/// Handler for the POST
/// /v0/admin/wallet/:id/orders/:id/assign-pool/:matching_pool route
pub struct AdminAssignOrderToMatchingPoolHandler {
    /// A handle to the relayer state
    state: State,
    /// A handle to send jobs to the relayer's handshake manager
    handshake_manager_queue: HandshakeManagerQueue,
}

impl AdminAssignOrderToMatchingPoolHandler {
    /// Constructor
    pub fn new(state: State, handshake_manager_queue: HandshakeManagerQueue) -> Self {
        Self { state, handshake_manager_queue }
    }
}

#[async_trait]
impl TypedHandler for AdminAssignOrderToMatchingPoolHandler {
    type Request = EmptyRequestResponse;
    type Response = EmptyRequestResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let order_id = parse_order_id_from_params(&params)?;
        let matching_pool = parse_matching_pool_from_url_params(&params)?;

        // Check that the wallet & order exist
        let wallet = self.state.get_wallet(&wallet_id).await?;
        if wallet.is_none() {
            return Err(not_found(ERR_WALLET_NOT_FOUND));
        }

        if !wallet.unwrap().contains_order(&order_id) {
            return Err(not_found(ERR_ORDER_NOT_FOUND));
        }

        // Check that the matching pool exists
        if !self.state.matching_pool_exists(matching_pool.clone()).await? {
            return Err(not_found(ERR_NO_MATCHING_POOL));
        }

        // Assign the order to the matching pool
        let waiter = self.state.assign_order_to_matching_pool(order_id, matching_pool).await?;
        waiter.await?;

        // Run the matching engine on the order
        let job = HandshakeExecutionJob::InternalMatchingEngine { order: order_id };
        self.handshake_manager_queue.send(job).map_err(internal_error)?;

        Ok(EmptyRequestResponse {})
    }
}

// -----------
// | Helpers |
// -----------

/// A helper to parse out a matching pool name from a query string
fn parse_include_fillable_from_query_params(params: &QueryParams) -> Result<bool, ApiServerError> {
    params.get(INCLUDE_FILLABLE_PARAM).map_or(Ok(false), |s| s.parse().map_err(bad_request))
}

/// Get the fillable amount of an order using the underlying wallet's balances,
/// & potentially the price of the base asset
async fn get_fillable_amount_and_price(
    meta: &OrderMetadata,
    state: &State,
    price_reporter_job_queue: &PriceReporterQueue,
) -> Result<(Amount, Price), ApiServerError> {
    let wallet_id =
        state.get_wallet_for_order(&meta.id).await?.ok_or(not_found(ERR_WALLET_NOT_FOUND))?;
    let wallet = state.get_wallet(&wallet_id).await?.ok_or(not_found(ERR_WALLET_NOT_FOUND))?;

    // Get an up-to-date order & balance.
    // The order stored on the `OrderMetadata` does not have the order amount
    // updated to account for fills, which will lead to an incorrect calculation
    // of the fillable amount.
    let order = wallet.get_order(&meta.id).ok_or(not_found(ERR_ORDER_NOT_FOUND))?;
    let balance = wallet.get_balance_for_order(order).ok_or(not_found(ERR_BALANCE_NOT_FOUND))?;

    // Buy orders are capitalized by the quote token, so we may need the price of
    // the base token to calculate how capitalized the order is
    let base_token = Token::from_addr_biguint(&order.base_mint);
    let quote_token = Token::from_addr_biguint(&order.quote_mint);
    let base_addr = base_token.get_addr().to_string();
    let quote_addr = quote_token.get_addr().to_string();

    let (price_tx, price_rx) = oneshot::channel();
    price_reporter_job_queue
        .send(PriceReporterJob::PeekPrice { base_token, quote_token, channel: price_tx })
        .map_err(internal_error)?;

    let price = match price_rx.await.map_err(internal_error)? {
        PriceReporterState::Nominal(report) => report.price,
        err_state => {
            return Err(internal_error(format!(
                "{ERR_NO_PRICE_DATA}: {base_addr} / {quote_addr} {err_state:?}"
            )))
        },
    };

    let price_fp = FixedPoint::from_f64_round_down(price);

    Ok((compute_max_amount(&price_fp, order, &balance), price))
}
