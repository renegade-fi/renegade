//! Request/response types for the admin api

// ---------------
// | HTTP Routes |
// ---------------

use common::types::{MatchingPoolName, wallet::OrderIdentifier};
use serde::{Deserialize, Serialize};

use crate::{
    http::wallet::CreateOrderOptions,
    types::{AdminOrderMetadata, ApiOrder},
};

use super::wallet::WalletUpdateAuthorization;

// Getter routes

/// Check whether the target node is a raft leader
pub const IS_LEADER_ROUTE: &str = "/v0/admin/is-leader";
/// Get the open orders managed by the node
pub const ADMIN_OPEN_ORDERS_ROUTE: &str = "/v0/admin/open-orders";
/// Get the order metadata for a given order
pub const ADMIN_ORDER_METADATA_ROUTE: &str = "/v0/admin/orders/:order_id/metadata";
/// Route to get the matching pool for an order
pub const ADMIN_GET_ORDER_MATCHING_POOL_ROUTE: &str = "/v0/admin/orders/:order_id/matching-pool";
/// Route to get all the matchable order IDs for a given wallet
pub const ADMIN_WALLET_MATCHABLE_ORDER_IDS_ROUTE: &str =
    "/v0/admin/wallet/:wallet_id/matchable-order-ids";

// Setter routes

/// Trigger a raft snapshot
pub const ADMIN_TRIGGER_SNAPSHOT_ROUTE: &str = "/v0/admin/trigger-snapshot";
/// Route to create a matching pool
pub const ADMIN_MATCHING_POOL_CREATE_ROUTE: &str = "/v0/admin/matching_pools/:matching_pool";
/// Route to destroy a matching pool
pub const ADMIN_MATCHING_POOL_DESTROY_ROUTE: &str =
    "/v0/admin/matching_pools/:matching_pool/destroy";
/// Route to create an order in a matching pool
pub const ADMIN_CREATE_ORDER_IN_MATCHING_POOL_ROUTE: &str =
    "/v0/admin/wallet/:wallet_id/order-in-pool";
/// Route to assign an order to a matching pool
pub const ADMIN_ASSIGN_ORDER_ROUTE: &str = "/v0/admin/orders/:order_id/assign-pool/:matching_pool";
/// Route to refresh the token mapping
pub const ADMIN_REFRESH_TOKEN_MAPPING_ROUTE: &str = "/v0/admin/refresh-token-mapping";
/// Route to refresh the match fee constants from the contract
pub const ADMIN_REFRESH_MATCH_FEES_ROUTE: &str = "/v0/admin/refresh-match-fees";

/// The response to an "is leader" request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IsLeaderResponse {
    /// Whether the target node is a raft leader
    pub leader: bool,
}

/// The response to an "open orders" request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenOrdersResponse {
    /// The open order IDs
    pub orders: Vec<OrderIdentifier>,
}

/// The request type to add a new order to a given wallet, within a non-global
/// matching pool
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateOrderInMatchingPoolRequest {
    /// The order to be created
    pub order: ApiOrder,
    /// The update authorization
    #[serde(flatten)]
    pub update_auth: WalletUpdateAuthorization,
    /// The matching pool to create the order in
    pub matching_pool: MatchingPoolName,
    /// The options for creating the order
    #[serde(default)]
    pub options: CreateOrderOptions,
}

/// The response to an admin "order metadata" request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminOrderMetadataResponse {
    /// The order metadata
    pub order: AdminOrderMetadata,
}

/// The response to a "get order matching pool" request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminGetOrderMatchingPoolResponse {
    /// The matching pool name for the order
    pub matching_pool: MatchingPoolName,
}

/// The response to a "get wallet matchable order IDs" request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminWalletMatchableOrderIdsResponse {
    /// The order IDs
    pub order_ids: Vec<OrderIdentifier>,
}
