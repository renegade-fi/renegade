//! Route handlers for order operations

use alloy::primitives::Address;
use async_trait::async_trait;
use external_api::{
    EmptyRequestResponse,
    http::order::{
        CancelOrderRequest, CancelOrderResponse, CreateOrderRequest, CreateOrderResponse,
        GetOrderByIdResponse, GetOrdersResponse, UpdateOrderRequest, UpdateOrderResponse,
    },
    types::OrderType,
};
use hyper::HeaderMap;
use state::State;
use types_account::order_auth::OrderAuth;
use types_tasks::CreateOrderTaskDescriptor;

use crate::{
    error::{ApiServerError, bad_request, not_found},
    http::helpers::append_task,
    param_parsing::{parse_account_id_from_params, parse_order_id_from_params},
    router::{QueryParams, TypedHandler, UrlParams},
};

// ------------------
// | Error Messages |
// ------------------

/// Error message for not implemented
const ERR_NOT_IMPLEMENTED: &str = "not implemented";
/// Error message for order not found
const ERR_ORDER_NOT_FOUND: &str = "order not found";

// -------------------
// | Order Handlers  |
// -------------------

/// Handler for GET /v2/account/:account_id/orders
pub struct GetOrdersHandler;

impl GetOrdersHandler {
    /// Constructor
    pub fn new() -> Self {
        Self
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
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        Err(ApiServerError::not_implemented(ERR_NOT_IMPLEMENTED))
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
        let order_account = self
            .state
            .get_account_id_for_order(&order_id)
            .await?
            .ok_or(ApiServerError::order_not_found(order_id))?;

        // Check the account id matches the order's account id
        if order_account != acct_id {
            return Err(ApiServerError::order_not_found(order_id));
        }

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
}

impl CreateOrderHandler {
    /// Constructor
    pub fn new(executor: Address, state: State) -> Self {
        Self { executor, state }
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
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        // Parse account ID from URL params
        let account_id = parse_account_id_from_params(&params)?;

        // TODO: Allow all order types
        let ty = req.order.order_type;
        if !matches!(ty, OrderType::PublicOrder) {
            return Err(bad_request("Only public orders are currently supported"));
        }

        // Convert order auth to an internal type
        let auth = OrderAuth::try_from(req.auth.clone())
            .map_err(|e| bad_request(format!("invalid order auth: {e}")))?;
        let order_id = req.order.id;
        let (intent, ring, metadata) = req.into_order_components()?;

        // Create the task descriptor
        let descriptor = CreateOrderTaskDescriptor::new(
            account_id,
            order_id,
            self.executor,
            intent,
            ring,
            metadata,
            auth,
        )
        .map_err(bad_request)?;
        let task_id = append_task(descriptor.into(), &self.state).await?;

        Ok(CreateOrderResponse { task_id, completed: false })
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
pub struct CancelOrderHandler;

impl CancelOrderHandler {
    /// Constructor
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TypedHandler for CancelOrderHandler {
    type Request = CancelOrderRequest;
    type Response = CancelOrderResponse;

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
