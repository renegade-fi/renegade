//! Route handlers for the admin API

use async_trait::async_trait;
use config::setup_token_remaps;
use darkpool_client::DarkpoolClient;
use external_api::{
    EmptyRequestResponse,
    http::admin::IsLeaderResponse,
    types::{GetOrderAdminResponse, GetOrdersAdminResponse},
};
use hyper::HeaderMap;
use state::State;
use tracing::info;
use types_core::Chain;

use crate::{
    error::{ApiServerError, internal_error},
    router::{QueryParams, TypedHandler, UrlParams},
};

// ------------------
// | Error Messages |
// ------------------

/// Error message for not implemented
const ERR_NOT_IMPLEMENTED: &str = "not implemented";

// -----------------------
// | Preserved Handlers  |
// -----------------------

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

/// Handler for the POST /v0/admin/trigger-snapshot route
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

/// Handler for the POST /v0/admin/refresh-token-mapping route
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

/// Handler for the POST /v0/admin/refresh-match-fees route
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
        info!("Refreshing external match fees from contract");

        Err(ApiServerError::not_implemented(ERR_NOT_IMPLEMENTED))
    }
}

// -------------------
// | v2 Admin Routes |
// -------------------

/// Handler for GET /v2/relayer-admin/orders
pub struct AdminGetOrdersHandler;

impl AdminGetOrdersHandler {
    /// Constructor
    pub fn new() -> Self {
        Self
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
        Err(ApiServerError::not_implemented(ERR_NOT_IMPLEMENTED))
    }
}

/// Handler for GET /v2/relayer-admin/orders/:order_id
pub struct AdminGetOrderByIdHandler;

impl AdminGetOrderByIdHandler {
    /// Constructor
    pub fn new() -> Self {
        Self
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
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        Err(ApiServerError::not_implemented(ERR_NOT_IMPLEMENTED))
    }
}
