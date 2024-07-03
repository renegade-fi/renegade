//! Route handlers for the admin API

// ------------------------
// | Admin Route Handlers |
// ------------------------

use async_trait::async_trait;
use external_api::{
    http::{
        admin::{CreateOrderInMatchingPoolRequest, IsLeaderResponse, OpenOrdersResponse},
        wallet::CreateOrderResponse,
    },
    EmptyRequestResponse,
};
use hyper::HeaderMap;
use job_types::handshake_manager::{HandshakeExecutionJob, HandshakeManagerQueue};
use state::State;

use crate::{
    error::{bad_request, internal_error, not_found, ApiServerError},
    router::{QueryParams, TypedHandler, UrlParams},
};

use super::{
    parse_matching_pool_from_params, parse_order_id_from_params, parse_wallet_id_from_params,
    wallet::{create_order, ERR_ORDER_NOT_FOUND},
};

// -------------
// | Constants |
// -------------

/// The matching pool already exists
const ERR_MATCHING_POOL_EXISTS: &str = "matching pool already exists";
/// The matching pool for the order does not exist
const ERR_NO_MATCHING_POOL: &str = "matching pool does not exist";

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
}

impl AdminOpenOrdersHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
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
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let order_ids = self.state.get_locally_matchable_orders().await?;
        let mut orders = Vec::new();
        for id in order_ids.into_iter() {
            let order = self.state.get_order_metadata(&id).await?;
            if let Some(meta) = order {
                orders.push(meta);
            }
        }

        Ok(OpenOrdersResponse { orders })
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
        let matching_pool = parse_matching_pool_from_params(&params)?;

        // Check that the matching pool does not already exist
        if self.state.matching_pool_exists(matching_pool.clone()).await.map_err(internal_error)? {
            return Err(bad_request(ERR_MATCHING_POOL_EXISTS));
        }

        let waiter =
            self.state.create_matching_pool(matching_pool).await.map_err(internal_error)?;

        waiter.await.map_err(internal_error)?;
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
        let matching_pool = parse_matching_pool_from_params(&params)?;

        let waiter =
            self.state.destroy_matching_pool(matching_pool).await.map_err(internal_error)?;

        waiter.await.map_err(internal_error)?;
        Ok(EmptyRequestResponse {})
    }
}

// ---------------------------------------------------
// | /wallet/:id/orders/matching_pool/:matching_pool |
// ---------------------------------------------------

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
        if !self.state.matching_pool_exists(matching_pool.clone()).await.map_err(internal_error)? {
            return Err(not_found(ERR_NO_MATCHING_POOL));
        }

        create_order(req.order, req.statement_sig, wallet_id, &self.state, Some(matching_pool))
            .await
    }
}

// -------------------------------------
// | /orders/:id/assign/:matching_pool |
// -------------------------------------

/// Handler for the POST /v0/admin/orders/:id/assign-pool/:matching_pool route
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
        let order_id = parse_order_id_from_params(&params)?;
        let matching_pool = parse_matching_pool_from_params(&params)?;

        // Check that the order exists
        if !self.state.contains_order(&order_id).await.map_err(internal_error)? {
            return Err(not_found(ERR_ORDER_NOT_FOUND));
        }

        // Check that the matching pool exists
        if !self.state.matching_pool_exists(matching_pool.clone()).await.map_err(internal_error)? {
            return Err(not_found(ERR_NO_MATCHING_POOL));
        }

        // Assign the order to the matching pool
        let waiter = self
            .state
            .assign_order_to_matching_pool(order_id, matching_pool)
            .await
            .map_err(internal_error)?;

        waiter.await.map_err(internal_error)?;

        // Run the matching engine on the order
        let job = HandshakeExecutionJob::InternalMatchingEngine { order: order_id };
        self.handshake_manager_queue.send(job).map_err(internal_error)?;

        Ok(EmptyRequestResponse {})
    }
}
