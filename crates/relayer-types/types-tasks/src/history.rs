//! Types for task history storage
#![cfg_attr(feature = "rkyv", allow(missing_docs))]

use alloy::primitives::Address;
use circuit_types::Amount;
#[cfg(feature = "rkyv")]
use darkpool_types::rkyv_remotes::AddressDef;
#[cfg(feature = "rkyv")]
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};
use types_core::AccountId;

use crate::descriptors::{
    QueuedTask, QueuedTaskState, TaskDescriptor, TaskIdentifier, TaskQueueKey,
};

/// A historical task executed by the task driver
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "rkyv", derive(Archive, RkyvSerialize, RkyvDeserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct HistoricalTask {
    /// The ID of the task
    pub id: TaskIdentifier,
    /// The state of the task
    pub state: QueuedTaskState,
    /// The time the task was created
    pub created_at: u64,
    /// The auxiliary information from the task descriptor that we keep in the
    /// history
    pub task_info: HistoricalTaskDescription,
}

impl HistoricalTask {
    /// Create a new historical task from a `QueuedTask`
    ///
    /// Returns `None` for tasks that should not be stored in history
    pub fn from_queued_task(key: TaskQueueKey, task: QueuedTask) -> Option<Self> {
        let desc = task.descriptor.clone();
        let task_info = HistoricalTaskDescription::from_task_descriptor(key, &desc)?;
        Some(Self { id: task.id, state: task.state, created_at: task.created_at, task_info })
    }
}

/// A historical description of a task
///
/// Separated out from the task descriptors as the descriptors may contain
/// runtime information irrelevant for storage
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "rkyv", derive(Archive, RkyvSerialize, RkyvDeserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub enum HistoricalTaskDescription {
    /// A new account was created
    NewAccount,
    /// A deposit was made
    Deposit {
        /// The account ID that deposited
        account_id: AccountId,
        /// The token that was deposited
        #[cfg_attr(feature = "rkyv", rkyv(with = AddressDef))]
        token: Address,
        /// The amount that was deposited
        amount: Amount,
    },
    /// A balance was created
    CreateBalance {
        /// The account ID that created the balance
        account_id: AccountId,
        /// The token for the balance
        #[cfg_attr(feature = "rkyv", rkyv(with = AddressDef))]
        token: Address,
        /// The amount for the balance
        amount: Amount,
    },
    /// An order was created
    CreateOrder {
        /// The account ID that created the order
        account_id: AccountId,
        /// The input token for the order
        #[cfg_attr(feature = "rkyv", rkyv(with = AddressDef))]
        token: Address,
        /// The input amount for the order
        amount: Amount,
    },
}

impl HistoricalTaskDescription {
    /// Create a historical task description from a task descriptor
    pub fn from_task_descriptor(_key: TaskQueueKey, desc: &TaskDescriptor) -> Option<Self> {
        match desc {
            TaskDescriptor::NewAccount(_) => Some(Self::NewAccount),
            TaskDescriptor::CreateOrder(desc) => Some(Self::CreateOrder {
                account_id: desc.account_id,
                token: desc.intent.in_token,
                amount: desc.intent.amount_in,
            }),
            TaskDescriptor::Deposit(desc) => Some(Self::Deposit {
                account_id: desc.account_id,
                token: desc.token,
                amount: desc.amount,
            }),
            TaskDescriptor::CreateBalance(desc) => Some(Self::CreateBalance {
                account_id: desc.account_id,
                token: desc.token,
                amount: desc.amount,
            }),
            TaskDescriptor::SettleInternalMatch(_) => None,
            TaskDescriptor::SettleExternalMatch(_) => None,
            TaskDescriptor::NodeStartup(_) => None,
            TaskDescriptor::Withdraw(_) => None,
        }
    }
}

// --- Mocks --- //

#[cfg(feature = "mocks")]
impl HistoricalTask {
    /// Create a mock historical task for testing
    pub fn mock() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        Self {
            id: TaskIdentifier::new_v4(),
            state: QueuedTaskState::Queued,
            created_at: COUNTER.fetch_add(1, Ordering::Relaxed),
            task_info: HistoricalTaskDescription::NewAccount,
        }
    }
}
