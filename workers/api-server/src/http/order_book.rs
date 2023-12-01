//! Groups routes and handlers for order book API operations

// ---------------
// | HTTP Routes |
// ---------------

use async_trait::async_trait;
use external_api::{
    http::order_book::{GetNetworkOrderByIdResponse, GetNetworkOrdersResponse},
    types::NetworkOrder,
    EmptyRequestResponse,
};
use hyper::HeaderMap;
use itertools::Itertools;
use state::RelayerState;

use crate::{
    error::{not_found, ApiServerError},
    router::{TypedHandler, UrlParams},
};

use super::parse_order_id_from_params;

// ------------------
// | Error Messages |
// ------------------

/// Error displayed when an order cannot be found in the network order book
const ERR_ORDER_NOT_FOUND: &str = "order not found in network order book";

// ---------------
// | HTTP Routes |
// ---------------

/// Returns all known network orders
pub(super) const GET_NETWORK_ORDERS_ROUTE: &str = "/v0/order_book/orders";
/// Returns the network order information of the specified order
pub(super) const GET_NETWORK_ORDER_BY_ID_ROUTE: &str = "/v0/order_book/orders/:order_id";

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
        _headers: HeaderMap,
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

/// Handler for the GET /order_book/orders route
#[derive(Clone, Debug)]
pub struct GetNetworkOrderByIdHandler {
    /// A copy of the relayer-global state
    pub global_state: RelayerState,
}

impl GetNetworkOrderByIdHandler {
    /// Constructor
    pub fn new(global_state: RelayerState) -> Self {
        Self { global_state }
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
    ) -> Result<Self::Response, ApiServerError> {
        let order_id = parse_order_id_from_params(&params)?;
        if let Some(order) =
            self.global_state.read_order_book().await.get_order_info(&order_id).await
        {
            Ok(GetNetworkOrderByIdResponse { order: order.into() })
        } else {
            Err(not_found(ERR_ORDER_NOT_FOUND.to_string()))
        }
    }
}
