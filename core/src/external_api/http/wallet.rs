//! Groups API type definitions for wallet API operations

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    external_api::{
        biguint_from_hex_string, biguint_to_hex_string,
        types::{Balance, Fee, Order, Wallet},
    },
    state::wallet::WalletIdentifier,
    tasks::driver::TaskIdentifier,
};

// --------------------
// | Wallet API Types |
// --------------------

/// The response type to get a wallet's information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetWalletResponse {
    /// The wallet requested by the client
    pub wallet: Wallet,
}

/// The request type to create a new wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateWalletRequest {
    /// The wallet info to be created
    pub wallet: Wallet,
}

/// The response type to a request to create a new wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateWalletResponse {
    /// The wallet identifier provisioned for the new wallet
    pub id: WalletIdentifier,
    /// The system-internal task ID that the client may use to query
    /// task status
    pub task_id: TaskIdentifier,
}

// ---------------------------
// | Wallet Orders API Types |
// ---------------------------

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

/// The request type to add a new order to a given wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateOrderRequest {
    /// The order to be created
    pub order: Order,
    /// A signature of the public variables used in the proof of
    /// VALID WALLET UPDATE by `sk_root`. This allows the contract
    /// to guarantee that the wallet updates are properly authorized
    ///
    /// TODO: For now this is just a blob, we will add this feature in
    /// a follow up
    pub public_var_sig: Vec<u8>,
}

/// The response type to a request that adds a new order to a wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateOrderResponse {
    /// The ID of the order created
    pub id: Uuid,
    /// The ID of the internal task created for the operation
    pub task_id: TaskIdentifier,
}

// -----------------------------
// | Wallet Balances API Types |
// -----------------------------

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

/// The request type to deposit a balance into the darkpool
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DepositBalanceRequest {
    /// The starknet account contract address to send the balance from
    #[serde(
        serialize_with = "biguint_to_hex_string",
        deserialize_with = "biguint_from_hex_string"
    )]
    pub from_addr: BigUint,
    /// The mint (ERC-20 contract address) of the token to deposit
    #[serde(
        serialize_with = "biguint_to_hex_string",
        deserialize_with = "biguint_from_hex_string"
    )]
    pub mint: BigUint,
    /// The amount of the token to deposit
    pub amount: BigUint,
    /// A signature of the public variables used in the proof of
    /// VALID WALLET UPDATE by `sk_root`. This allows the contract
    /// to guarantee that the wallet updates are properly authorized
    ///
    /// TODO: For now this is just a blob, we will add this feature in
    /// a follow up
    pub public_var_sig: Vec<u8>,
}

/// The response type to a request to deposit into the darkpool
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DepositBalanceResponse {
    /// The ID of the internal task created for this request
    /// May be used by the client to query task status
    pub task_id: TaskIdentifier,
}

/// The request type to withdraw a balance from the Darkpool
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithdrawBalanceRequest {
    /// The destination address to withdraw the balance to
    #[serde(
        serialize_with = "biguint_to_hex_string",
        deserialize_with = "biguint_from_hex_string"
    )]
    pub destination_addr: BigUint,
    /// The amount of the token to withdraw
    pub amount: BigUint,
    /// A signature of the public variables used in the proof of
    /// VALID WALLET UPDATE by `sk_root`. This allows the contract
    /// to guarantee that the wallet updates are properly authorized
    ///
    /// TODO: For now this is just a blob, we will add this feature in
    /// a follow up
    pub public_var_sig: Vec<u8>,
}

/// The response type to a request to withdraw a balance
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithdrawBalanceResponse {
    /// The ID of the task allocated for this operation
    pub task_id: TaskIdentifier,
}

// -------------------------
// | Wallet Fees API Types |
// -------------------------

/// The response type to get a wallet's fees
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetFeesResponse {
    /// The fees in a given wallet
    pub fees: Vec<Fee>,
}
