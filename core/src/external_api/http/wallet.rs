//! Groups API type definitions for wallet API operations

use serde::{Deserialize, Serialize};

use crate::external_api::types::{Balance, Fee, Order, Wallet};

/// The response type to get a wallet's information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetWalletResponse {
    /// The wallet requested by the client
    pub wallet: Wallet,
}

/// The response type to get a wallet's orders
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetOrdersResponse {
    /// The orders within a given wallet
    pub orders: Vec<Order>,
}

/// The response type to get a single order by ID
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetOrderByIdResponse {
    /// The order requested
    pub order: Order,
}

/// The response type to get a wallet's balances
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetBalancesResponse {
    /// The balances in the given wallet
    pub balances: Vec<Balance>,
}

/// The response type to get a single balance by mint
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetBalanceByMintResponse {
    /// The requested balance
    pub balance: Balance,
}

/// The response type to get a wallet's fees
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetFeesResponse {
    /// The fees in a given wallet
    pub fees: Vec<Fee>,
}
