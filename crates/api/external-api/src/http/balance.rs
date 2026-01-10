//! HTTP route definitions and request/response types for balance operations

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::{ApiBalance, ApiDepositPermit, ApiSchnorrPublicKey};

// ---------------
// | HTTP Routes |
// ---------------

/// Route to get balances for an account
pub const GET_BALANCES_ROUTE: &str = "/v2/account/:account_id/balances";
/// Route to get a balance by mint
pub const GET_BALANCE_BY_MINT_ROUTE: &str = "/v2/account/:account_id/balances/:mint";
/// Route to deposit a balance
pub const DEPOSIT_BALANCE_ROUTE: &str = "/v2/account/:account_id/balances/:mint/deposit";
/// Route to withdraw a balance
pub const WITHDRAW_BALANCE_ROUTE: &str = "/v2/account/:account_id/balances/:mint/withdraw";

// -------------------
// | Request/Response |
// -------------------

/// Response for get balances
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetBalancesResponse {
    /// The balances
    pub balances: Vec<ApiBalance>,
}

/// Response for get balance by mint
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetBalanceByMintResponse {
    /// The balance
    pub balance: ApiBalance,
}

/// Request to deposit a balance
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DepositBalanceRequest {
    /// The address to deposit from
    pub from_address: String,
    /// The amount to deposit
    pub amount: String,
    /// The authority public key
    pub authority: ApiSchnorrPublicKey,
    /// The permit for the deposit
    pub permit: ApiDepositPermit,
}

/// Response for deposit balance
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DepositBalanceResponse {
    /// The task ID for the deposit
    pub task_id: Uuid,
    /// The balance after deposit
    pub balance: ApiBalance,
    /// Whether the operation has completed
    pub completed: bool,
}

/// Request to withdraw a balance
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithdrawBalanceRequest {
    /// The amount to withdraw
    pub amount: String,
    /// The signature authorizing the withdrawal (base64 encoded)
    pub signature: String,
}

/// Response for withdraw balance
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithdrawBalanceResponse {
    /// The task ID for the withdrawal
    pub task_id: Uuid,
    /// The balance after withdrawal
    pub balance: ApiBalance,
    /// Whether the operation has completed
    pub completed: bool,
}
