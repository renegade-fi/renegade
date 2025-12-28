//! API types for task history
//!
//! We redefine types from the `common` crate here to provide better enum JSON
//! serialization. Our `common` types cannot use the internally tagged
//! representations as the `bincode` crate does not support them

use std::str::FromStr;

use darkpool_types::{intent::Intent, settlement_obligation::SettlementObligation};
use serde::{Deserialize, Serialize};
use serde_json::Number;
use types_tasks::{
    HistoricalTask, HistoricalTaskDescription, QueuedTask, TaskIdentifier, TaskQueueKey,
};
use util::hex::address_to_hex_string;

// -----------
// | Helpers |
// -----------

/// Converts a `u128` to a `Number`
fn u128_to_number(value: u128) -> Number {
    Number::from_str(&value.to_string()).unwrap()
}

// ---------
// | Types |
// ---------

/// A historical task
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiHistoricalTask {
    /// The id of the task
    pub id: TaskIdentifier,
    /// The state of the task
    pub state: String,
    /// The time the task was created
    pub created_at: u64,
    /// The axillary information that specifies the transformation the task took
    pub task_info: ApiHistoricalTaskDescription,
}

impl From<HistoricalTask> for ApiHistoricalTask {
    fn from(value: HistoricalTask) -> Self {
        Self {
            id: value.id,
            state: value.state.display_description(),
            created_at: value.created_at,
            task_info: value.task_info.into(),
        }
    }
}

impl ApiHistoricalTask {
    /// Convert from a queued task
    pub fn from_queued_task(key: TaskQueueKey, task: &QueuedTask) -> Option<Self> {
        let task_info =
            HistoricalTaskDescription::from_task_descriptor(key, &task.descriptor)?.into();
        let state = task.state.display_description();
        Some(Self { id: task.id, state, created_at: task.created_at, task_info })
    }
}

/// A historical description of a task
///
/// Separated out from the task descriptors as the descriptors may contain
/// runtime information irrelevant for storage
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "task_type")]
pub enum ApiHistoricalTaskDescription {
    /// A new account was created
    NewAccount,
    /// A wallet was looked up
    LookupWallet,
    /// A wallet was refreshed
    RefreshWallet,
}

impl From<HistoricalTaskDescription> for ApiHistoricalTaskDescription {
    fn from(value: HistoricalTaskDescription) -> Self {
        match value {
            HistoricalTaskDescription::NewAccount => Self::NewAccount,
        }
    }
}

/// A type representing a match in a historical task
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiHistoricalMatch {
    /// The base mint matched
    pub in_token: String,
    /// The quote mint matched
    pub out_token: String,
    /// The amount input by the user to the trade
    pub amount_in: Number,
    /// The amount output to the user from the trade
    pub amount_out: Number,
}

impl From<SettlementObligation> for ApiHistoricalMatch {
    fn from(value: SettlementObligation) -> Self {
        let in_token = address_to_hex_string(&value.input_token);
        let out_token = address_to_hex_string(&value.output_token);
        let amount_in = u128_to_number(value.amount_in);
        let amount_out = u128_to_number(value.amount_out);
        Self { in_token, out_token, amount_in, amount_out }
    }
}

/// A type representing a description of an update wallet task
///
/// Differentiates between order vs balance updates, and holds fields for
/// display
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "update_type")]
pub enum ApiAccountUpdateType {
    /// Deposit a balance
    Deposit {
        /// The deposited mint
        mint: String,
        /// The amount deposited
        amount: Number,
    },
    /// Withdraw a balance
    Withdraw {
        /// The withdrawn mint
        mint: String,
        /// The amount withdrawn
        amount: Number,
    },
    /// Place an order
    PlaceOrder {
        /// The order that was placed
        #[serde(flatten)]
        order: AccountUpdateIntent,
    },
    /// Cancel an order
    CancelOrder {
        /// The order that was cancelled
        #[serde(flatten)]
        order: AccountUpdateIntent,
    },
}

/// Represents an order in a wallet update type
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountUpdateIntent {
    /// The mint of the base token
    pub in_token: String,
    /// The mint of the quote token
    pub out_token: String,
    /// The volume of the order
    pub amount: Number,
}

impl From<Intent> for AccountUpdateIntent {
    fn from(value: Intent) -> Self {
        let in_token = address_to_hex_string(&value.in_token);
        let out_token = address_to_hex_string(&value.out_token);
        let amount = u128_to_number(value.amount_in);
        Self { in_token, out_token, amount }
    }
}
