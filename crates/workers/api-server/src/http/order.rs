//! Route handlers for order operations

use alloy::primitives::Address;
use async_trait::async_trait;
use constants::GLOBAL_MATCHING_POOL;
use external_api::{
    EmptyRequestResponse,
    http::order::{
        CancelOrderRequest, CancelOrderResponse, CreateOrderRequest, CreateOrderResponse,
        GetOrderByIdResponse, GetOrdersResponse, UpdateOrderRequest, UpdateOrderResponse,
    },
    types::OrderType,
};
use hyper::HeaderMap;
use itertools::Itertools;
use job_types::task_driver::TaskDriverQueue;
use renegade_solidity_abi::v2::IDarkpoolV2::SignatureWithNonce;
use state::State;
use types_account::{OrderId, order::PrivacyRing};
use types_core::AccountId;
use types_tasks::{CancelOrderTaskDescriptor, CreateOrderTaskDescriptor};

use crate::{
    error::{ApiServerError, bad_request, not_found},
    http::helpers::append_task,
    param_parsing::{
        parse_account_id_from_params, parse_order_id_from_params, should_block_on_task,
    },
    router::{QueryParams, TypedHandler, UrlParams},
};

// ------------------
// | Error Messages |
// ------------------

/// Error message for not implemented
const ERR_NOT_IMPLEMENTED: &str = "not implemented";
/// Error message for order not found
const ERR_ORDER_NOT_FOUND: &str = "order not found";
/// Error message for invalid order type (not Ring0)
const ERR_INVALID_ORDER_TYPE: &str =
    "only public orders (Ring0) can be cancelled via this endpoint";
/// Error message for missing order auth
const ERR_ORDER_AUTH_NOT_FOUND: &str = "order auth not found";
/// Error message for invalid order auth type
const ERR_INVALID_ORDER_AUTH: &str = "order auth is not for a public order";

// -------------------
// | Order Handlers  |
// -------------------

/// Handler for GET /v2/account/:account_id/orders
pub struct GetOrdersHandler {
    /// A handle to the relayer's state
    state: State,
}

impl GetOrdersHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for GetOrdersHandler {
    type Request = EmptyRequestResponse;
    type Response = GetOrdersResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let account_id = parse_account_id_from_params(&params)?;
        let orders = self.state.get_account_orders(&account_id).await?;
        let orders = orders.into_iter().map(Into::into).collect_vec();

        // TODO: Paginate
        Ok(GetOrdersResponse { orders, next_page_token: None })
    }
}

/// Handler for GET /v2/account/:account_id/orders/:order_id
pub struct GetOrderByIdHandler {
    /// A handle to the relayer's state
    state: State,
}

impl GetOrderByIdHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for GetOrderByIdHandler {
    type Request = EmptyRequestResponse;
    type Response = GetOrderByIdResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let acct_id = parse_account_id_from_params(&params)?;
        let order_id = parse_order_id_from_params(&params)?;
        verify_order_belongs_to_account(order_id, acct_id, &self.state).await?;

        // Fetch the order
        let order =
            self.state.get_account_order(&order_id).await?.ok_or(not_found(ERR_ORDER_NOT_FOUND))?;
        Ok(GetOrderByIdResponse { order: order.into() })
    }
}

/// Handler for POST /v2/account/:account_id/orders
pub struct CreateOrderHandler {
    /// The local relayer's executor address
    executor: Address,
    /// A handle to the relayer's state
    state: State,
    /// The task driver queue
    task_queue: TaskDriverQueue,
}

impl CreateOrderHandler {
    /// Constructor
    pub fn new(executor: Address, state: State, task_queue: TaskDriverQueue) -> Self {
        Self { executor, state, task_queue }
    }
}

#[async_trait]
impl TypedHandler for CreateOrderHandler {
    type Request = CreateOrderRequest;
    type Response = CreateOrderResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        req: Self::Request,
        params: UrlParams,
        query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let blocking = should_block_on_task(&query_params);

        // Parse account ID from URL params
        let account_id = parse_account_id_from_params(&params)?;

        // TODO: Allow all order types
        let ty = req.order.order_type;
        if !matches!(ty, OrderType::PublicOrder) {
            return Err(bad_request("Only public orders are currently supported"));
        }

        // Convert order auth to an internal type
        let order_id = req.order.id;
        let auth = req.get_order_auth(self.executor)?;
        let (intent, ring, metadata) = req.into_order_components()?;

        // Create the task descriptor with the global matching pool
        let descriptor = CreateOrderTaskDescriptor::new(
            account_id,
            order_id,
            intent,
            ring,
            metadata,
            auth,
            GLOBAL_MATCHING_POOL.to_string(),
        )
        .map_err(bad_request)?;
        let task_id =
            append_task(descriptor.into(), blocking, &self.state, &self.task_queue).await?;

        Ok(CreateOrderResponse { task_id, completed: true })
    }
}

/// Handler for POST /v2/account/:account_id/orders/:order_id/update
pub struct UpdateOrderHandler;
impl UpdateOrderHandler {
    /// Constructor
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TypedHandler for UpdateOrderHandler {
    type Request = UpdateOrderRequest;
    type Response = UpdateOrderResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        Err(ApiServerError::not_implemented(ERR_NOT_IMPLEMENTED))
    }
}

/// Handler for POST /v2/account/:account_id/orders/:order_id/cancel
pub struct CancelOrderHandler {
    /// A handle to the relayer's state
    state: State,
    /// The task driver queue
    task_queue: TaskDriverQueue,
}

impl CancelOrderHandler {
    /// Constructor
    pub fn new(state: State, task_queue: TaskDriverQueue) -> Self {
        Self { state, task_queue }
    }
}

#[async_trait]
impl TypedHandler for CancelOrderHandler {
    type Request = CancelOrderRequest;
    type Response = CancelOrderResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        req: Self::Request,
        params: UrlParams,
        query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let blocking = should_block_on_task(&query_params);

        // Parse account_id and order_id from URL params
        let account_id = parse_account_id_from_params(&params)?;
        let order_id = parse_order_id_from_params(&params)?;
        verify_order_belongs_to_account(order_id, account_id, &self.state).await?;

        // Convert the cancel signature from the request
        let cancel_signature: SignatureWithNonce =
            req.cancel_signature.try_into().map_err(bad_request)?;

        // Fetch the order and verify it
        let order = self
            .state
            .get_account_order(&order_id)
            .await?
            .ok_or(ApiServerError::order_not_found(order_id))?;
        if order.ring != PrivacyRing::Ring0 {
            return Err(bad_request(ERR_INVALID_ORDER_TYPE));
        }

        // Fetch the order auth and extract the intent signature
        let order_auth = self
            .state
            .get_order_auth(&order_id)
            .await?
            .ok_or(not_found(ERR_ORDER_AUTH_NOT_FOUND))?;

        // Create the task descriptor
        let descriptor =
            CancelOrderTaskDescriptor::new(account_id, order_id, order_auth, cancel_signature)
                .map_err(bad_request)?;

        // Append the task and return the task ID
        let task_id =
            append_task(descriptor.into(), blocking, &self.state, &self.task_queue).await?;
        Ok(CancelOrderResponse { task_id, completed: true })
    }
}

// -----------
// | Helpers |
// -----------

/// Verify that an order belongs to a given account
async fn verify_order_belongs_to_account(
    order_id: OrderId,
    account_id: AccountId,
    state: &State,
) -> Result<(), ApiServerError> {
    let order_account = state
        .get_account_id_for_order(&order_id)
        .await?
        .ok_or(ApiServerError::order_not_found(order_id))?;

    if order_account != account_id {
        return Err(ApiServerError::order_not_found(order_id));
    }

    Ok(())
}
