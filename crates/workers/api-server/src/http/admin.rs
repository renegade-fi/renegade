//! Route handlers for the admin API

use alloy::primitives::Address;
use async_trait::async_trait;
use config::setup_token_remaps;
use constants::GLOBAL_MATCHING_POOL;
use darkpool_client::DarkpoolClient;
use external_api::{
    EmptyRequestResponse,
    http::{
        admin::IsLeaderResponse,
        order::{CreateOrderInPoolRequest, CreateOrderResponse},
    },
    types::{
        ApiAdminOrder, GetOrderAdminResponse, GetOrdersAdminResponse, OrderType,
        TaskQueuePausedResponse, order::ApiOrder,
    },
};
use hyper::HeaderMap;
use job_types::task_driver::TaskDriverQueue;
use state::State;
use tracing::info;
use types_core::{Chain, Token, get_all_tokens};
use types_tasks::CreateOrderTaskDescriptor;
use util::on_chain::{set_default_protocol_fee, set_protocol_fee};

use crate::{
    error::{ApiServerError, bad_request, internal_error, not_found},
    http::helpers::append_task,
    param_parsing::{
        parse_account_id_from_params, parse_matching_pool_from_url_params,
        parse_order_id_from_params, should_block_on_task,
    },
    router::{QueryParams, TypedHandler, UrlParams},
};

// -----------------------
// | Preserved Handlers  |
// -----------------------

/// Handler for the GET /v2/admin/is-leader route
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

/// Handler for the POST /v2/admin/trigger-snapshot route
pub struct AdminTriggerSnapshotHandler {
    /// A handle to the relayer state
    state: State,
}

impl AdminTriggerSnapshotHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for AdminTriggerSnapshotHandler {
    type Request = EmptyRequestResponse;
    type Response = EmptyRequestResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        self.state.trigger_snapshot().await?;
        Ok(EmptyRequestResponse {})
    }
}

/// Handler for the POST /v2/admin/refresh-token-mapping route
pub struct AdminRefreshTokenMappingHandler {
    /// The chain to fetch a token mapping for
    chain: Chain,
}

impl AdminRefreshTokenMappingHandler {
    /// Constructor
    pub fn new(chain: Chain) -> Self {
        Self { chain }
    }
}

#[async_trait]
impl TypedHandler for AdminRefreshTokenMappingHandler {
    type Request = EmptyRequestResponse;
    type Response = EmptyRequestResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        info!("Refreshing token mapping from repo");

        let chain = self.chain;
        tokio::task::spawn_blocking(move || setup_token_remaps(None /* remap_file */, chain))
            .await
            .map_err(internal_error) // Tokio join error
            .and_then(|r| r.map_err(internal_error))?; // Token remap setup error

        Ok(EmptyRequestResponse {})
    }
}

/// Handler for the POST /v2/admin/refresh-match-fees route
pub struct AdminRefreshMatchFeesHandler {
    /// A handle to the relayer state
    darkpool_client: DarkpoolClient,
}

impl AdminRefreshMatchFeesHandler {
    /// Constructor
    pub fn new(darkpool_client: DarkpoolClient) -> Self {
        Self { darkpool_client }
    }
}

#[async_trait]
impl TypedHandler for AdminRefreshMatchFeesHandler {
    type Request = EmptyRequestResponse;
    type Response = EmptyRequestResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        info!("Refreshing match fees from contract");

        // Fetch the default protocol fee from the contract
        let protocol_fee = self.darkpool_client.get_default_protocol_fee().await?;
        set_default_protocol_fee(protocol_fee);

        // Fetch the external match fee overrides for each mint
        let usdc = Token::usdc().get_alloy_address();
        let tokens = get_all_tokens().into_iter().filter(|t| t.get_alloy_address() != usdc);
        for token in tokens {
            if token.get_alloy_address() == usdc {
                continue;
            }

            // Fetch the fee override from the contract
            let addr = token.get_alloy_address();
            let fee = self.darkpool_client.get_protocol_fee(addr, usdc).await?;

            // Write the fee into the mapping
            set_protocol_fee(&addr, &usdc, fee);
        }

        Ok(EmptyRequestResponse {})
    }
}

// -------------------
// | v2 Admin Routes |
// -------------------

/// Handler for GET /v2/relayer-admin/orders
pub struct AdminGetOrdersHandler {
    /// A handle to the relayer state
    state: State,
}

impl AdminGetOrdersHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for AdminGetOrdersHandler {
    type Request = EmptyRequestResponse;
    type Response = GetOrdersAdminResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        // Get all orders with their admin metadata
        let orders_data =
            self.state.get_all_orders_with_matching_pool().await.map_err(internal_error)?;

        // Convert to API types
        let orders: Vec<ApiAdminOrder> = orders_data
            .into_iter()
            .map(|(order, account_id, matching_pool)| ApiAdminOrder {
                order: ApiOrder::from(order),
                account_id,
                matching_pool: matching_pool.to_string(),
            })
            .collect();

        // TODO: Paginate
        Ok(GetOrdersAdminResponse { orders, next_page_token: None })
    }
}

/// Error message for order auth not found
const ERR_ORDER_AUTH_NOT_FOUND: &str = "order auth not found";

/// Handler for GET /v2/relayer-admin/orders/:order_id
pub struct AdminGetOrderByIdHandler {
    /// A handle to the relayer state
    state: State,
}

impl AdminGetOrderByIdHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for AdminGetOrderByIdHandler {
    type Request = EmptyRequestResponse;
    type Response = GetOrderAdminResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let order_id = parse_order_id_from_params(&params)?;
        let account_id = self
            .state
            .get_account_id_for_order(&order_id)
            .await?
            .ok_or(ApiServerError::order_not_found(order_id))?;

        let order = self
            .state
            .get_account_order(&order_id)
            .await?
            .ok_or(ApiServerError::order_not_found(order_id))?;

        // Fetch the order auth
        let auth = self
            .state
            .get_order_auth(&order_id)
            .await?
            .ok_or(not_found(ERR_ORDER_AUTH_NOT_FOUND))?
            .into();

        // Convert to API type
        let matching_pool = self.state.get_matching_pool_for_order(&order_id).await?;
        let order: ApiAdminOrder =
            ApiAdminOrder { order: ApiOrder::from(order), account_id, matching_pool };

        Ok(GetOrderAdminResponse { order, auth })
    }
}

/// Handler for GET /v2/relayer-admin/account/:account_id/orders
pub struct AdminGetAccountOrdersHandler {
    /// A handle to the relayer state
    state: State,
}

impl AdminGetAccountOrdersHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for AdminGetAccountOrdersHandler {
    type Request = EmptyRequestResponse;
    type Response = GetOrdersAdminResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let account_id = parse_account_id_from_params(&params)?;

        // Get orders with matching pool for this account
        let orders_data = self
            .state
            .get_account_orders_with_matching_pool(&account_id)
            .await
            .map_err(internal_error)?;

        // Convert to API types
        let orders = orders_data
            .into_iter()
            .map(|(order, matching_pool)| ApiAdminOrder {
                order: ApiOrder::from(order),
                account_id,
                matching_pool: matching_pool.to_string(),
            })
            .collect();

        // TODO: Paginate
        Ok(GetOrdersAdminResponse { orders, next_page_token: None })
    }
}

/// Handler for GET /v2/relayer-admin/account/:account_id/tasks/paused
pub struct AdminGetTaskQueuePausedHandler {
    /// A handle to the relayer state
    state: State,
}

impl AdminGetTaskQueuePausedHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for AdminGetTaskQueuePausedHandler {
    type Request = EmptyRequestResponse;
    type Response = TaskQueuePausedResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let account_id = parse_account_id_from_params(&params)?;
        let paused =
            self.state.is_queue_paused_serial(&account_id).await.map_err(internal_error)?;

        Ok(TaskQueuePausedResponse { paused })
    }
}

// --------------------------
// | Matching Pool Handlers |
// --------------------------

/// Error message when a matching pool does not exist
const ERR_MATCHING_POOL_NOT_FOUND: &str = "matching pool does not exist";
/// Error message when trying to destroy a non-empty matching pool
const ERR_MATCHING_POOL_NOT_EMPTY: &str = "matching pool is not empty";
/// Error message when trying to create or destroy the global matching pool
const ERR_CANNOT_MODIFY_GLOBAL_POOL: &str = "cannot create or destroy the global matching pool";

/// Handler for the POST /v2/admin/matching-pools/:matching_pool route
#[derive(Clone)]
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

        // Cannot create the global matching pool
        if matching_pool == GLOBAL_MATCHING_POOL {
            return Err(bad_request(ERR_CANNOT_MODIFY_GLOBAL_POOL));
        }

        // Check that the matching pool does not already exist
        if self.state.matching_pool_exists(matching_pool.clone()).await? {
            return Ok(EmptyRequestResponse {});
        }

        let waiter = self.state.create_matching_pool(matching_pool).await?;
        waiter.await?;

        Ok(EmptyRequestResponse {})
    }
}

/// Handler for the POST /v2/admin/matching-pools/:matching_pool/destroy route
#[derive(Clone)]
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

        // Cannot destroy the global matching pool
        if matching_pool == GLOBAL_MATCHING_POOL {
            return Err(bad_request(ERR_CANNOT_MODIFY_GLOBAL_POOL));
        }

        // Check that the matching pool exists
        if !self.state.matching_pool_exists(matching_pool.clone()).await? {
            return Err(not_found(ERR_MATCHING_POOL_NOT_FOUND));
        }

        // Check that the matching pool is empty
        if !self.state.matching_pool_is_empty(matching_pool.clone()).await? {
            return Err(bad_request(ERR_MATCHING_POOL_NOT_EMPTY));
        }

        let waiter = self.state.destroy_matching_pool(matching_pool).await?;
        waiter.await?;

        Ok(EmptyRequestResponse {})
    }
}

// ---------------------------------
// | Create Order In Pool Handlers |
// ---------------------------------

/// Handler for
/// POST /v2/relayer-admin/account/:account_id/orders/create-order-in-pool
pub struct AdminCreateOrderInPoolHandler {
    /// The local relayer's executor address
    executor: Address,
    /// A handle to the relayer state
    state: State,
    /// The task driver queue
    task_queue: TaskDriverQueue,
}

impl AdminCreateOrderInPoolHandler {
    /// Constructor
    pub fn new(executor: Address, state: State, task_queue: TaskDriverQueue) -> Self {
        Self { executor, state, task_queue }
    }
}

#[async_trait]
impl TypedHandler for AdminCreateOrderInPoolHandler {
    type Request = CreateOrderInPoolRequest;
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

        // Only public orders are currently supported
        let ty = req.order.order_type;
        if !matches!(ty, OrderType::PublicOrder) {
            return Err(bad_request("Only public orders are currently supported"));
        }

        // Validate matching pool exists
        let matching_pool = req.matching_pool.clone();
        if !self.state.matching_pool_exists(matching_pool.clone()).await? {
            return Err(not_found(ERR_MATCHING_POOL_NOT_FOUND));
        }

        // Convert order auth to an internal type, validating the permit
        let order_id = req.order.id;
        let auth = req.get_order_auth(self.executor).map_err(bad_request)?;
        let (intent, ring, metadata) = req.into_order_components();

        // Create the task descriptor with the specified matching pool
        let descriptor = CreateOrderTaskDescriptor::new(
            account_id,
            order_id,
            intent,
            ring,
            metadata,
            auth,
            matching_pool,
        )
        .map_err(bad_request)?;
        let task_id =
            append_task(descriptor.into(), blocking, &self.state, &self.task_queue).await?;

        Ok(CreateOrderResponse { task_id, completed: true })
    }
}
