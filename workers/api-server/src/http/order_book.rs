//! Groups routes and handlers for order book API operations

// ---------------
// | HTTP Routes |
// ---------------

use std::collections::HashMap;

use async_trait::async_trait;
use common::types::wallet::OrderIdentifier;
use external_api::{
    http::order_book::{GetNetworkOrderByIdResponse, GetNetworkOrdersResponse},
    types::NetworkOrder,
    EmptyRequestResponse,
};
use hyper::{HeaderMap, StatusCode};
use itertools::Itertools;
use state::RelayerState;

use crate::{
    error::ApiServerError,
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

/// Asynchronously retrieves the timestamp of an order by its identifier from the global state.
/// 
/// # Arguments
/// 
/// * `order_id` - The identifier of the order
/// * `global_state` - The global state containing the order
/// 
/// # Returns
/// 
/// An optional `u64` representing the timestamp of the order, or `None` if the order is not found.
async fn get_timestamp_by_order_id(
    order_id: &OrderIdentifier,
    global_state: &RelayerState,
) -> Option<u64> {
    if let Some(order) = global_state.get_order(order_id).await {
        Some(order.timestamp)
    } else {
        None
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
        let mut order_timestamp_map: HashMap<OrderIdentifier, u64> = HashMap::new();
        for order in self
            .global_state
            .read_order_book()
            .await
            .get_order_book_snapshot()
            .await
            .values()
        {
            if let Some(timestamp) = get_timestamp_by_order_id(&order.id, &self.global_state).await
            {
                order_timestamp_map.insert(order.id, timestamp);
            }
        }

        let orders: Vec<NetworkOrder> = self
            .global_state
            .read_order_book()
            .await
            .get_order_book_snapshot()
            .await
            .values()
            .cloned()
            .map(|order| {
                let mut network_order: NetworkOrder = order.clone().into();
                if let Some(timestamp) = order_timestamp_map.get(&order.id) {
                    network_order.timestamp = *timestamp;
                }
                network_order
            })
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
        if let Some(order) = self
            .global_state
            .read_order_book()
            .await
            .get_order_info(&order_id)
            .await
        {
            Ok(GetNetworkOrderByIdResponse {
                order: order.into(),
            })
        } else {
            Err(ApiServerError::HttpStatusCode(
                StatusCode::NOT_FOUND,
                ERR_ORDER_NOT_FOUND.to_string(),
            ))
        }
    }
}
