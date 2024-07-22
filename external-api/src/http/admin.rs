//! Request/response types for the admin api

// ---------------
// | HTTP Routes |
// ---------------

use circuit_types::Amount;
use common::types::{wallet::order_metadata::OrderMetadata, MatchingPoolName};
use serde::{Deserialize, Serialize};

use crate::types::ApiOrder;

/// Check whether the target node is a raft leader
pub const IS_LEADER_ROUTE: &str = "/v0/admin/is-leader";
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
/// as well as the fillable amount of the order
/// given the underlying wallet's balances and potentially
/// the current price of the base asset
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenOrder {
    /// The order metadata
    pub order: OrderMetadata,
    /// The fillable amount of the order
    pub fillable: Amount,
}

/// The request type to add a new order to a given wallet, within a non-global
/// matching pool
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateOrderInMatchingPoolRequest {
    /// The order to be created
    pub order: ApiOrder,
    /// A signature of the circuit statement used in the proof of
    /// VALID WALLET UPDATE by `sk_root`. This allows the contract
    /// to guarantee that the wallet updates are properly authorized
    pub statement_sig: Vec<u8>,
    /// The matching pool to create the order in
    pub matching_pool: MatchingPoolName,
}

/// The response to an "order metadata" request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminOrderMetadataResponse {
    /// The order metadata
    pub order: OrderMetadata,
}
