//! API types for task history
//!
//! We redefine types from the `common` crate here to provide better enum JSON
//! serialization. Our `common` types cannot use the internally tagged
//! representations as the `bincode` crate does not support them

use std::str::FromStr;

use circuit_types::{order::Order, r#match::MatchResult};
use common::types::tasks::{
    HistoricalTask, HistoricalTaskDescription, QueuedTaskState, TaskIdentifier, WalletUpdateType,
};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_json::Number;

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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiHistoricalTask {
    /// The id of the task
    pub id: TaskIdentifier,
    /// The state of the task
    pub state: QueuedTaskState,
    /// The time the task was created
    pub created_at: u64,
    /// The axillary information that specifies the transformation the task took
    pub task_info: ApiHistoricalTaskDescription,
}

impl From<HistoricalTask> for ApiHistoricalTask {
    fn from(value: HistoricalTask) -> Self {
        Self {
            id: value.id,
            state: value.state,
            created_at: value.created_at,
            task_info: value.task_info.into(),
        }
    }
}

/// A historical description of a task
///
/// Separated out from the task descriptors as the descriptors may contain
/// runtime information irrelevant for storage
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "task_type")]
pub enum ApiHistoricalTaskDescription {
    /// A new wallet was created
    NewWallet,
    /// An update to a wallet
    UpdateWallet(ApiWalletUpdateType),
    /// A match was settled
    SettleMatch(MatchResult),
    /// A fee was paid
    PayOfflineFee,
}

impl From<HistoricalTaskDescription> for ApiHistoricalTaskDescription {
    fn from(value: HistoricalTaskDescription) -> Self {
        match value {
            HistoricalTaskDescription::NewWallet => Self::NewWallet,
            HistoricalTaskDescription::UpdateWallet(update) => {
                Self::UpdateWallet(ApiWalletUpdateType::from(update))
            },
            HistoricalTaskDescription::SettleMatch(match_result) => Self::SettleMatch(match_result),
            HistoricalTaskDescription::PayOfflineFee => Self::PayOfflineFee,
        }
    }
}

/// A type representing a description of an update wallet task
///
/// Differentiates between order vs balance updates, and holds fields for
/// display
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "update_type")]
pub enum ApiWalletUpdateType {
    /// Deposit a balance
    Deposit {
        /// The deposited mint
        mint: BigUint,
        /// The amount deposited
        amount: Number,
    },
    /// Withdraw a balance
    Withdraw {
        /// The withdrawn mint
        mint: BigUint,
        /// The amount withdrawn
        amount: Number,
    },
    /// Place an order
    PlaceOrder {
        /// The order to place
        order: Order,
    },
    /// Cancel an order
    CancelOrder {
        /// The order that was cancelled
        order: Order,
    },
}

impl From<WalletUpdateType> for ApiWalletUpdateType {
    fn from(value: WalletUpdateType) -> Self {
        match value {
            WalletUpdateType::Deposit { mint, amount } => {
                Self::Deposit { mint, amount: u128_to_number(amount) }
            },
            WalletUpdateType::Withdraw { mint, amount } => {
                Self::Withdraw { mint, amount: u128_to_number(amount) }
            },
            WalletUpdateType::PlaceOrder { order } => Self::PlaceOrder { order },
            WalletUpdateType::CancelOrder { order } => Self::CancelOrder { order },
        }
    }
}
