//! Request/response types for the admin api

use serde::{Deserialize, Serialize};

// ---------
// | Paths |
// ---------

/// Check whether the target node is a raft leader
pub const IS_LEADER_ROUTE: &str = "/v2/admin/is-leader";
/// Trigger a raft snapshot
pub const ADMIN_TRIGGER_SNAPSHOT_ROUTE: &str = "/v2/admin/trigger-snapshot";
/// Route to refresh the token mapping
pub const ADMIN_REFRESH_TOKEN_MAPPING_ROUTE: &str = "/v2/admin/refresh-token-mapping";
/// Route to refresh the match fee constants from the contract
pub const ADMIN_REFRESH_MATCH_FEES_ROUTE: &str = "/v2/admin/refresh-match-fees";
/// Route to get all orders as an admin
pub const ADMIN_GET_ORDERS_ROUTE: &str = "/v2/relayer-admin/orders";
/// Route to get an order by ID as an admin
pub const ADMIN_GET_ORDER_BY_ID_ROUTE: &str = "/v2/relayer-admin/orders/:order_id";

// -------------------
// | Request/Response |
// -------------------

/// The response to an "is leader" request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IsLeaderResponse {
    /// Whether the target node is a raft leader
    pub leader: bool,
}

// Re-export v2 admin types from types module
pub use crate::types::{ApiAdminOrder, GetOrderAdminResponse, GetOrdersAdminResponse};
