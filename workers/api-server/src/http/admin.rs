//! Route handlers for the admin API

// ------------------------
// | Admin Route Handlers |
// ------------------------

use async_trait::async_trait;
use external_api::{
    http::admin::{IsLeaderResponse, OpenOrdersResponse},
    EmptyRequestResponse,
};
use hyper::HeaderMap;
use state::State;

use crate::{
    error::ApiServerError,
    router::{QueryParams, TypedHandler, UrlParams},
};

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
