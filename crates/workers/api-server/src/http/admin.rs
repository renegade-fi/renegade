//! Route handlers for the admin API

use async_trait::async_trait;
use config::setup_token_remaps;
use darkpool_client::DarkpoolClient;
use external_api::{
    EmptyRequestResponse,
    http::admin::IsLeaderResponse,
    types::{ApiAdminOrder, GetOrderAdminResponse, GetOrdersAdminResponse, order::ApiOrder},
};
use hyper::HeaderMap;
use state::State;
use tracing::info;
use types_core::{Chain, Token, get_all_tokens};
use util::on_chain::{set_default_protocol_fee, set_protocol_fee};

use crate::{
    error::{ApiServerError, internal_error},
    param_parsing::parse_order_id_from_params,
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

        // Convert to API type
        let matching_pool = self.state.get_matching_pool_for_order(&order_id).await?;
        let order: ApiAdminOrder =
            ApiAdminOrder { order: ApiOrder::from(order), account_id, matching_pool };

        Ok(GetOrderAdminResponse { order })
    }
}
