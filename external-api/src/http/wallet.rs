//! Groups API type definitions for wallet API operations

use circuit_types::balance::Balance;
use common::types::{
    tasks::TaskIdentifier,
    wallet::{order_metadata::OrderMetadata, WalletIdentifier},
};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    deserialize_biguint_from_hex_string, serialize_biguint_to_hex_string,
    types::{ApiKeychain, ApiOrder, ApiWallet},
};

// ---------------
// | HTTP Routes |
// ---------------

/// Create a new wallet
pub const CREATE_WALLET_ROUTE: &str = "/v0/wallet";
/// Find a wallet in contract storage
pub const FIND_WALLET_ROUTE: &str = "/v0/wallet/lookup";
/// Returns the wallet information for the given id
pub const GET_WALLET_ROUTE: &str = "/v0/wallet/:wallet_id";
/// Get the wallet at the "back of the queue", i.e. the speculatively updated
/// wallet as if all enqueued wallet tasks had completed
pub const BACK_OF_QUEUE_WALLET_ROUTE: &str = "/v0/wallet/:wallet_id/back_of_queue";
/// Route to the orders of a given wallet
pub const WALLET_ORDERS_ROUTE: &str = "/v0/wallet/:wallet_id/orders";
/// Returns a single order by the given identifier
pub const GET_ORDER_BY_ID_ROUTE: &str = "/v0/wallet/:wallet_id/orders/:order_id";
/// Updates a given order
pub const UPDATE_ORDER_ROUTE: &str = "/v0/wallet/:wallet_id/orders/:order_id/update";
/// Cancels a given order
pub const CANCEL_ORDER_ROUTE: &str = "/v0/wallet/:wallet_id/orders/:order_id/cancel";
/// Returns the balances within a given wallet
pub const GET_BALANCES_ROUTE: &str = "/v0/wallet/:wallet_id/balances";
/// Returns the balance associated with the given mint
pub const GET_BALANCE_BY_MINT_ROUTE: &str = "/v0/wallet/:wallet_id/balances/:mint";
/// Deposits an ERC-20 token into the darkpool
pub const DEPOSIT_BALANCE_ROUTE: &str = "/v0/wallet/:wallet_id/balances/deposit";
/// Withdraws an ERC-20 token from the darkpool
pub const WITHDRAW_BALANCE_ROUTE: &str = "/v0/wallet/:wallet_id/balances/:mint/withdraw";

/// Returns the order history of a wallet
pub const ORDER_HISTORY_ROUTE: &str = "/v0/wallet/:wallet_id/order-history";

// --------------------
// | Wallet API Types |
// --------------------

/// The response type to get a wallet's information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetWalletResponse {
    /// The wallet requested by the client
    pub wallet: ApiWallet,
}

/// The request type to create a new wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateWalletRequest {
    /// The wallet info to be created
    pub wallet: ApiWallet,
}

/// The response type to a request to create a new wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateWalletResponse {
    /// The wallet identifier provisioned for the new wallet
    pub wallet_id: WalletIdentifier,
    /// The system-internal task ID that the client may use to query
    /// task status
    pub task_id: TaskIdentifier,
}

/// The request type to find a wallet in contract storage and begin managing it
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FindWalletRequest {
    /// The ID to handle the wallet by
    pub wallet_id: WalletIdentifier,
    /// The seed for the wallet's blinder CSPRNG
    pub blinder_seed: BigUint,
    /// The seed for the wallet's secret share CSPRNG
    pub secret_share_seed: BigUint,
    /// The keychain to use for management after the wallet is found
    pub key_chain: ApiKeychain,
}

/// The response type to a request to find a wallet in contract storage
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FindWalletResponse {
    /// The ID to handle the wallet by
    pub wallet_id: WalletIdentifier,
    /// The ID of the task created on behalf of this request
    pub task_id: TaskIdentifier,
}

// ---------------------------
// | Wallet Orders API Types |
// ---------------------------

/// The response type to get a wallet's orders
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetOrdersResponse {
    /// The orders within a given wallet
    pub orders: Vec<ApiOrder>,
}
/// The response type to get a single order by ID
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetOrderByIdResponse {
    /// The order requested
    pub order: ApiOrder,
}

/// The request type to add a new order to a given wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateOrderRequest {
    /// The order to be created
    pub order: ApiOrder,
    /// A signature of the circuit statement used in the proof of
    /// VALID WALLET UPDATE by `sk_root`. This allows the contract
    /// to guarantee that the wallet updates are properly authorized
    pub statement_sig: Vec<u8>,
}

/// The response type to a request that adds a new order to a wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateOrderResponse {
    /// The ID of the order created
    pub id: Uuid,
    /// The ID of the internal task created for the operation
    pub task_id: TaskIdentifier,
}

/// The request type to update an order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateOrderRequest {
    /// The order to be updated
    pub order: ApiOrder,
    /// A signature of the circuit statement used in the proof of
    /// VALID WALLET UPDATE by `sk_root`. This allows the contract
    /// to guarantee that the wallet updates are properly authorized
    pub statement_sig: Vec<u8>,
}

/// The response type to update an order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateOrderResponse {
    /// The ID of the task allocated for this request
    pub task_id: TaskIdentifier,
}

/// The request type to cancel a given order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CancelOrderRequest {
    /// A signature of the circuit statement used in the proof of
    /// VALID WALLET UPDATE by `sk_root`. This allows the contract
    /// to guarantee that the wallet updates are properly authorized
    pub statement_sig: Vec<u8>,
}

/// The response type to a request to cancel a given order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CancelOrderResponse {
    /// The ID of the task allocated for this request
    pub task_id: TaskIdentifier,
    /// The order information of the now-cancelled order
    pub order: ApiOrder,
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
    /// The arbitrum account contract address to send the balance from
    #[serde(
        serialize_with = "serialize_biguint_to_hex_string",
        deserialize_with = "deserialize_biguint_from_hex_string"
    )]
    pub from_addr: BigUint,
    /// The mint (ERC-20 contract address) of the token to deposit
    #[serde(
        serialize_with = "serialize_biguint_to_hex_string",
        deserialize_with = "deserialize_biguint_from_hex_string"
    )]
    pub mint: BigUint,
    /// The amount of the token to deposit
    pub amount: BigUint,
    /// A signature of the wallet commitment used in the proof of
    /// VALID WALLET UPDATE by `sk_root`. This allows the contract
    /// to guarantee that the wallet updates are properly authorized
    ///
    /// TODO: For now this is just a blob, we will add this feature in
    /// a follow up
    pub wallet_commitment_sig: Vec<u8>,
    /// The nonce used in the associated Permit2 permit
    pub permit_nonce: BigUint,
    /// The deadline used in the associated Permit2 permit
    pub permit_deadline: BigUint,
    /// The signature over the associated Permit2 permit, allowing
    /// the contract to guarantee that the deposit is sourced from
    /// the correct account
    pub permit_signature: Vec<u8>,
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
        serialize_with = "serialize_biguint_to_hex_string",
        deserialize_with = "deserialize_biguint_from_hex_string"
    )]
    pub destination_addr: BigUint,
    /// The amount of the token to withdraw
    pub amount: BigUint,
    /// A signature of the wallet commitment used in the proof of
    /// VALID WALLET UPDATE by `sk_root`. This allows the contract
    /// to guarantee that the wallet updates are properly authorized
    ///
    /// TODO: For now this is just a blob, we will add this feature in
    /// a follow up
    pub wallet_commitment_sig: Vec<u8>,
    /// A signature over the external transfer, allowing the contract
    /// to guarantee that the withdrawal is directed at the correct
    /// recipient
    pub external_transfer_sig: Vec<u8>,
}

/// The response type to a request to withdraw a balance
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithdrawBalanceResponse {
    /// The ID of the task allocated for this operation
    pub task_id: TaskIdentifier,
}

// ---------------------------
// | Order History API Types |
// ---------------------------

/// The response type for order history
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetOrderHistoryResponse {
    /// A history of orders in the wallet
    pub orders: Vec<OrderMetadata>,
}
