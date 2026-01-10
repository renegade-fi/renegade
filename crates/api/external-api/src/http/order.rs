//! HTTP route definitions and request/response types for order operations

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::{ApiOrder, ApiOrderCore, OrderAuth};

// ---------------
// | HTTP Routes |
// ---------------

/// Route to get orders for an account
pub const GET_ORDERS_ROUTE: &str = "/v2/account/:account_id/orders";
/// Route to create a new order
pub const CREATE_ORDER_ROUTE: &str = "/v2/account/:account_id/orders";
/// Route to get an order by ID
pub const GET_ORDER_BY_ID_ROUTE: &str = "/v2/account/:account_id/orders/:order_id";
/// Route to update an order
pub const UPDATE_ORDER_ROUTE: &str = "/v2/account/:account_id/orders/:order_id/update";
/// Route to cancel an order
pub const CANCEL_ORDER_ROUTE: &str = "/v2/account/:account_id/orders/:order_id/cancel";

// -------------------
// | Request/Response |
// -------------------

/// Response for get orders
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetOrdersResponse {
    /// The orders
    pub orders: Vec<ApiOrder>,
    /// The next page token for pagination
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<i64>,
}

/// Response for get order by ID
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetOrderByIdResponse {
    /// The order
    pub order: ApiOrder,
}

/// Request to create a new order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateOrderRequest {
    /// The order to create
    pub order: ApiOrderCore,
    /// The authorization for the order
    pub auth: OrderAuth,
    /// Whether to precompute the cancellation proof
    pub precompute_cancellation_proof: bool,
}

/// Response for create order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateOrderResponse {
    /// The task ID for the creation
    pub task_id: Uuid,
    /// The created order
    pub order: ApiOrder,
    /// Whether the operation has completed
    pub completed: bool,
}

/// Request to update an order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateOrderRequest {
    /// The updated order
    pub order: ApiOrderCore,
}

/// Response for update order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateOrderResponse {
    /// The updated order
    pub order: ApiOrder,
}

/// Request to cancel an order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CancelOrderRequest {
    /// The signature authorizing the cancellation (base64 encoded)
    pub signature: String,
}

/// Response for cancel order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CancelOrderResponse {
    /// The task ID for the cancellation
    pub task_id: Uuid,
    /// The cancelled order
    pub order: ApiOrder,
    /// Whether the operation has completed
    pub completed: bool,
}
