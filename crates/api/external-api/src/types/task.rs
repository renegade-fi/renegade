//! API types for tasks

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------
// | Task Types |
// ---------------

/// A task in the system
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiTask {
    /// The task identifier
    pub id: Uuid,
    /// The current state of the task
    pub state: String,
    /// The creation timestamp
    pub created_at: u64,
    /// The task description/type
    pub task_info: ApiTaskDescription,
}

/// The type/description of a task
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApiTaskDescription {
    /// Create a new account
    CreateAccount,
    /// Sync an account
    SyncAccount,
    /// Deposit funds
    Deposit,
    /// Pay a fee
    PayFee,
    /// Withdraw funds
    Withdraw,
    /// Create an order
    CreateOrder,
    /// Update an order
    UpdateOrder,
    /// Cancel an order
    CancelOrder,
    /// Settle a match
    SettleMatch,
}
