//! API types for admin requests

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::order::ApiOrder;

// -------------------
// | v2 Admin Types  |
// -------------------

/// An admin order with additional metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiAdminOrder {
    /// The order details
    pub order: ApiOrder,
    /// The account ID that owns the order
    pub account_id: Uuid,
    /// The matching pool the order is in
    pub matching_pool: String,
}

/// Response for admin get orders request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetOrdersAdminResponse {
    /// The orders
    pub orders: Vec<ApiAdminOrder>,
    /// The next page token for pagination
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<i64>,
}

/// Response for admin get order by ID request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetOrderAdminResponse {
    /// The order
    pub order: ApiAdminOrder,
}

/// Response for checking if an account's task queue is paused
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskQueuePausedResponse {
    /// Whether the task queue is paused
    pub paused: bool,
}
