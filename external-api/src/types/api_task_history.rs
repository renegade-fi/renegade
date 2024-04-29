//! API types for task history
//!
//! We redefine types from the `common` crate here to provide better enum JSON
//! serialization. Our `common` types cannot use the internally tagged
//! representations as the `bincode` crate does not support them

use std::str::FromStr;

use circuit_types::{
    order::{Order, OrderSide},
    r#match::MatchResult,
};
use common::types::tasks::{
    HistoricalTask, HistoricalTaskDescription, QueuedTask, QueuedTaskState, TaskIdentifier,
    TaskQueueKey, WalletUpdateType,
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

impl ApiHistoricalTask {
    /// Convert from a queued task
    pub fn from_queued_task(key: TaskQueueKey, task: QueuedTask) -> Option<Self> {
        let task_info =
            HistoricalTaskDescription::from_task_descriptor(&task.descriptor, key)?.into();
        Some(Self { id: task.id, state: task.state, created_at: task.created_at, task_info })
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
    SettleMatch(ApiHistoricalMatch),
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
            HistoricalTaskDescription::SettleMatch(match_result) => {
                Self::SettleMatch(match_result.into())
            },
            HistoricalTaskDescription::PayOfflineFee => Self::PayOfflineFee,
        }
    }
}

/// A type representing a match in a historical task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiHistoricalMatch {
    /// The base mint matched
    pub base: BigUint,
    /// The quote mint matched
    pub quote: BigUint,
    /// The volume matched
    pub volume: Number,
    /// The direction the local party
    pub is_sell: bool,
}

impl From<MatchResult> for ApiHistoricalMatch {
    fn from(value: MatchResult) -> Self {
        Self {
            base: value.base_mint,
            quote: value.quote_mint,
            volume: u128_to_number(value.base_amount),
            is_sell: value.direction,
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
        /// The order that was placed
        #[serde(flatten)]
        order: WalletUpdateOrder,
    },
    /// Cancel an order
    CancelOrder {
        /// The order that was cancelled
        #[serde(flatten)]
        order: WalletUpdateOrder,
    },
}

/// Represents an order in a wallet update type
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletUpdateOrder {
    /// The mint of the base token
    pub base: BigUint,
    /// The mint of the quote token
    pub quote: BigUint,
    /// The side of the order
    pub side: OrderSide,
    /// The volume of the order
    pub amount: Number,
}

impl From<Order> for WalletUpdateOrder {
    fn from(value: Order) -> Self {
        Self {
            base: value.base_mint,
            quote: value.quote_mint,
            side: value.side,
            amount: u128_to_number(value.amount),
        }
    }
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
            WalletUpdateType::PlaceOrder { order } => {
                Self::PlaceOrder { order: WalletUpdateOrder::from(order) }
            },
            WalletUpdateType::CancelOrder { order } => {
                Self::CancelOrder { order: WalletUpdateOrder::from(order) }
            },
        }
    }
}
