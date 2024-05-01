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
    HistoricalTask, HistoricalTaskDescription, QueuedTask, TaskIdentifier, TaskQueueKey,
    WalletUpdateType,
};
use serde::{Deserialize, Serialize};
use serde_json::Number;
use util::hex::biguint_to_hex_string;

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
    pub fn from_queued_task(key: TaskQueueKey, task: QueuedTask) -> Option<Self> {
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
    pub base: String,
    /// The quote mint matched
    pub quote: String,
    /// The volume matched
    pub volume: Number,
    /// The direction the local party
    pub is_sell: bool,
}

impl From<MatchResult> for ApiHistoricalMatch {
    fn from(value: MatchResult) -> Self {
        let base = biguint_to_hex_string(&value.base_mint);
        let quote = biguint_to_hex_string(&value.quote_mint);
        let volume = u128_to_number(value.base_amount);
        Self { base, quote, volume, is_sell: value.direction }
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
    pub base: String,
    /// The mint of the quote token
    pub quote: String,
    /// The side of the order
    pub side: OrderSide,
    /// The volume of the order
    pub amount: Number,
}

impl From<Order> for WalletUpdateOrder {
    fn from(value: Order) -> Self {
        let base = biguint_to_hex_string(&value.base_mint);
        let quote = biguint_to_hex_string(&value.quote_mint);
        let amount = u128_to_number(value.amount);
        Self { base, quote, side: value.side, amount }
    }
}

impl From<WalletUpdateType> for ApiWalletUpdateType {
    fn from(value: WalletUpdateType) -> Self {
        match value {
            WalletUpdateType::Deposit { mint, amount } => {
                let mint = biguint_to_hex_string(&mint);
                let amount = u128_to_number(amount);
                Self::Deposit { mint, amount }
            },
            WalletUpdateType::Withdraw { mint, amount } => {
                let mint = biguint_to_hex_string(&mint);
                let amount = u128_to_number(amount);
                Self::Withdraw { mint, amount }
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
