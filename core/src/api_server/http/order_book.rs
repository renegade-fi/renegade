//! Groups routes and handlers for order book API operations

// ---------------
// | HTTP Routes |
// ---------------

use async_trait::async_trait;
use itertools::Itertools;

use crate::{
    api_server::{
        error::ApiServerError,
        router::{TypedHandler, UrlParams},
    },
    external_api::{
        http::order_book::GetNetworkOrdersResponse, types::NetworkOrder, EmptyRequestResponse,
    },
    state::RelayerState,
};

/// Returns all known network orders
pub(super) const GET_NETWORK_ORDERS_ROUTE: &str = "/v0/order_book/orders";

// ----------------------
// | Order Book Routers |
// ----------------------

/// Handler for the GET /order_book/orders route
#[derive(Clone, Debug)]
pub struct GetNetworkOrdersHandler {
    /// A copy of the relayer-global state
    pub global_state: RelayerState,
}

impl GetNetworkOrdersHandler {
    /// Constructor
    pub fn new(global_state: RelayerState) -> Self {
        Self { global_state }
    }
}

#[async_trait]
impl TypedHandler for GetNetworkOrdersHandler {
    type Request = EmptyRequestResponse;
    type Response = GetNetworkOrdersResponse;

    async fn handle_typed(
        &self,
        _req: Self::Request,
        _params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        let orders: Vec<NetworkOrder> = self
            .global_state
            .read_order_book()
            .await
            .get_order_book_snapshot()
            .await
            .values()
            .cloned()
            .map(|order| order.into())
            .collect_vec();

        Ok(GetNetworkOrdersResponse { orders })
    }
}
