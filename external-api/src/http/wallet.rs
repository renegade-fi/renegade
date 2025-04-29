//! Groups API type definitions for wallet API operations

use circuit_types::{balance::Balance, elgamal::DecryptionKey, note::Note};
use common::types::{
    tasks::TaskIdentifier,
    wallet::{order_metadata::OrderMetadata, WalletIdentifier},
};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::{ApiOrder, ApiPrivateKeychain, ApiWallet};
use crate::{
    deserialize_biguint_from_hex_string, deserialize_bytes_or_base64, deserialize_limbs_or_number,
    serialize_biguint_to_hex_addr,
};

/// The type encapsulating a wallet update's authorization parameters
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletUpdateAuthorization {
    /// A signature of the circuit statement used in the proof of
    /// VALID WALLET UPDATE by `sk_root`. This allows the contract
    /// to guarantee that the wallet updates are properly authorized
    #[serde(deserialize_with = "deserialize_bytes_or_base64")]
    pub statement_sig: Vec<u8>,
    /// The new public root key to rotate to if desired by the client
    ///
    /// Hex encoded
    pub new_root_key: Option<String>,
}

// ---------------
// | HTTP Routes |
// ---------------

/// Create a new wallet
pub const CREATE_WALLET_ROUTE: &str = "/v0/wallet";
/// Find a wallet in contract storage
pub const FIND_WALLET_ROUTE: &str = "/v0/wallet/lookup";
/// Refresh a wallet from on-chain state
pub const REFRESH_WALLET_ROUTE: &str = "/v0/wallet/:wallet_id/refresh";
/// Returns the wallet information for the given id
pub const GET_WALLET_ROUTE: &str = "/v0/wallet/:wallet_id";
/// Get the wallet at the "back of the queue", i.e. the speculatively updated
/// wallet as if all enqueued wallet tasks had completed
pub const BACK_OF_QUEUE_WALLET_ROUTE: &str = "/v0/wallet/:wallet_id/back-of-queue";
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
/// Redeem a note into a wallet
pub const REDEEM_NOTE_ROUTE: &str = "/v0/wallet/:wallet_id/redeem-note";
/// Pays all wallet fees
pub const PAY_FEES_ROUTE: &str = "/v0/wallet/:wallet_id/pay-fees";

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
    /// The blinder seed to use for the wallet
    pub blinder_seed: BigUint,
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
    /// The private keychain to use for management after the wallet is found
    pub private_keychain: ApiPrivateKeychain,
}

/// The response type to a request to find a wallet in contract storage
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FindWalletResponse {
    /// The ID to handle the wallet by
    pub wallet_id: WalletIdentifier,
    /// The ID of the task created on behalf of this request
    pub task_id: TaskIdentifier,
}

/// The response type to refresh a wallet's state from on-chain
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RefreshWalletResponse {
    /// The task that refreshes the state
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
    /// The authorization parameters for the update
    #[serde(flatten)]
    pub update_auth: WalletUpdateAuthorization,
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
    /// The authorization parameters for the update
    #[serde(flatten)]
    pub update_auth: WalletUpdateAuthorization,
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
    /// The authorization parameters for the update
    #[serde(flatten)]
    pub update_auth: WalletUpdateAuthorization,
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
    /// The EVM account contract address to send the balance from
    #[serde(
        serialize_with = "serialize_biguint_to_hex_addr",
        deserialize_with = "deserialize_biguint_from_hex_string"
    )]
    pub from_addr: BigUint,
    /// The mint (ERC-20 contract address) of the token to deposit
    #[serde(
        serialize_with = "serialize_biguint_to_hex_addr",
        deserialize_with = "deserialize_biguint_from_hex_string"
    )]
    pub mint: BigUint,
    /// The amount of the token to deposit
    #[serde(deserialize_with = "deserialize_limbs_or_number")]
    pub amount: BigUint,
    /// The update authorization parameters
    #[serde(flatten)]
    pub update_auth: WalletUpdateAuthorization,
    /// The nonce used in the associated Permit2 permit
    #[serde(deserialize_with = "deserialize_limbs_or_number")]
    pub permit_nonce: BigUint,
    /// The deadline used in the associated Permit2 permit
    #[serde(deserialize_with = "deserialize_limbs_or_number")]
    pub permit_deadline: BigUint,
    /// The signature over the associated Permit2 permit, allowing
    /// the contract to guarantee that the deposit is sourced from
    /// the correct account
    #[serde(deserialize_with = "deserialize_bytes_or_base64")]
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
        serialize_with = "serialize_biguint_to_hex_addr",
        deserialize_with = "deserialize_biguint_from_hex_string"
    )]
    pub destination_addr: BigUint,
    /// The amount of the token to withdraw
    #[serde(deserialize_with = "deserialize_limbs_or_number")]
    pub amount: BigUint,
    /// The authorization parameters for the update
    #[serde(flatten)]
    pub update_auth: WalletUpdateAuthorization,
    /// A signature over the external transfer, allowing the contract
    /// to guarantee that the withdrawal is directed at the correct
    /// recipient
    #[serde(deserialize_with = "deserialize_bytes_or_base64")]
    pub external_transfer_sig: Vec<u8>,
}

/// The response type to a request to withdraw a balance
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithdrawBalanceResponse {
    /// The ID of the task allocated for this operation
    pub task_id: TaskIdentifier,
}

/// A request to redeem a note into a wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedeemNoteRequest {
    /// The note to be redeemed
    pub note: Note,
    /// The decryption key to use for authorization
    pub decryption_key: DecryptionKey,
}

/// A response to redeem a note
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedeemNoteResponse {
    /// The ID of the task allocated for this operation
    pub task_id: TaskIdentifier,
}

// ------------------
// | Fees API Types |
// ------------------

/// The response type to a request to pay all wallet fees
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PayFeesResponse {
    /// The fee payment tasks allocated for the request
    pub task_ids: Vec<TaskIdentifier>,
}

// ---------------------------
// | Order History API Types |
// ---------------------------

/// The response type for order history
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetOrderHistoryResponse {
    /// A history of orders in the wallet
    pub orders: Vec<OrderMetadata>,
    /// A token to use for pagination in subsequent requests
    pub pagination_token: Option<String>,
}
