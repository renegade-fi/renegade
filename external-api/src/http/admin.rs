//! Request/response types for the admin api

// ---------------
// | HTTP Routes |
// ---------------

use circuit_types::Amount;
use common::types::{
    wallet::{order_metadata::OrderMetadata, WalletIdentifier},
    MatchingPoolName, Price,
};
use serde::{Deserialize, Serialize};

use crate::types::ApiOrder;

use super::wallet::WalletUpdateAuthorization;

/// Check whether the target node is a raft leader
pub const IS_LEADER_ROUTE: &str = "/v0/admin/is-leader";
/// Trigger a raft snapshot
pub const ADMIN_TRIGGER_SNAPSHOT_ROUTE: &str = "/v0/admin/trigger-snapshot";
/// Get the open orders managed by the node
pub const ADMIN_OPEN_ORDERS_ROUTE: &str = "/v0/admin/open-orders";
/// Get the order metadata for a given order
pub const ADMIN_ORDER_METADATA_ROUTE: &str = "/v0/admin/orders/:order_id/metadata";
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
/// Route to get the matching pool for an order
pub const ADMIN_GET_ORDER_MATCHING_POOL_ROUTE: &str = "/v0/admin/orders/:order_id/matching-pool";

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
    pub orders: Vec<OpenOrder>,
}

/// An open order, containing the order's metadata
/// and potentially the fillable amount of the order
/// given the underlying wallet's balances and
/// the current price of the base asset
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenOrder {
    /// The order metadata
    pub order: OrderMetadata,
    /// The ID of the wallet containing the order
    pub wallet_id: WalletIdentifier,
    /// The fillable amount of the order, if calculated
    pub fillable: Option<Amount>,
    /// The price used to calculate the fillable amount, if calculated
    pub price: Option<Price>,
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
}

/// The response to an "order metadata" request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminOrderMetadataResponse {
    /// The order metadata
    pub order: OrderMetadata,
}

/// The response to a "get order matching pool" request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminGetOrderMatchingPoolResponse {
    /// The matching pool name for the order
    pub matching_pool: MatchingPoolName,
}
