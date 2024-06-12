//! Request/response types for the admin api

// ---------------
// | HTTP Routes |
// ---------------

use common::types::wallet::order_metadata::OrderMetadata;
use serde::{Deserialize, Serialize};

/// Check whether the target node is a raft leader
pub const IS_LEADER_ROUTE: &str = "/v0/admin/is-leader";
/// Get the open orders managed by the node
pub const ADMIN_OPEN_ORDERS_ROUTE: &str = "/v0/admin/open-orders";

/// The response to an "is leader" request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IsLeaderResponse {
    /// Whether the target node is a raft leader
    pub leader: bool,
}

/// The response to an "open orders" request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenOrdersResponse {
    /// The open orders
    pub orders: Vec<OrderMetadata>,
}
