use darkpool_types::{deposit::Deposit, withdrawal::Withdrawal};
use serde::{Deserialize, Serialize};
use types_core::AccountId;

/// A deposit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositEvent {
    /// The ID of the account that made the deposit
    pub account_id: AccountId,
    /// The transfer that occurred
    pub transfer: Deposit,
}

impl DepositEvent {
    /// Creates a new deposit event
    pub fn new(account_id: AccountId, transfer: Deposit) -> Self {
        Self { account_id, transfer }
    }

    /// Returns a human-readable description of the event
    pub fn describe(&self) -> String {
        "Deposit".to_string()
    }
}

/// A withdrawal event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalEvent {
    /// The ID of the account that made the withdrawal
    pub account_id: AccountId,
    /// The transfer that occurred
    pub transfer: Withdrawal,
}

impl WithdrawalEvent {
    /// Creates a new withdrawal event
    pub fn new(account_id: AccountId, transfer: Withdrawal) -> Self {
        Self { account_id, transfer }
    }

    /// Returns a human-readable description of the event
    pub fn describe(&self) -> String {
        "Withdrawal".to_string()
    }
}
