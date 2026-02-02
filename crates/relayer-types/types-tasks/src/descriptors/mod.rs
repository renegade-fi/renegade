//! Descriptors of tasks used to parameterize their execution
// Allow missing docs on generated rkyv Archived types
#![cfg_attr(feature = "rkyv", allow(missing_docs))]

mod cancel_order;
mod create_balance;
mod create_order;
mod deposit;
mod new_account;
mod node_startup;
mod refresh_account;
mod settle_external_match;
mod settle_internal_match;
mod withdraw;

pub use cancel_order::*;
pub use create_balance::*;
pub use create_order::*;
pub use deposit::*;
pub use new_account::*;
pub use node_startup::*;
pub use refresh_account::*;
pub use settle_external_match::*;
pub use settle_internal_match::*;
pub use withdraw::*;

#[cfg(feature = "rkyv")]
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize, with::Skip};
use serde::{Deserialize, Serialize};
use types_core::AccountId;
use util::{
    get_current_time_millis,
    telemetry::propagation::{TraceContext, set_parent_span_from_context, trace_context},
};
use uuid::Uuid;

/// A type alias for the identifier underlying a task
pub type TaskIdentifier = Uuid;
/// A type alias for the task queue key type, used to index tasks by shared
/// resource
pub type TaskQueueKey = Uuid;

/// A task in the task queue
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "rkyv", derive(Archive, RkyvSerialize, RkyvDeserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct QueuedTask {
    /// The ID of the task
    pub id: TaskIdentifier,
    /// The state of the task
    pub state: QueuedTaskState,
    /// The task descriptor
    pub descriptor: TaskDescriptor,
    /// The time at which the task was created
    pub created_at: u64,
    /// The tracing context in which the task was created
    #[serde(default)]
    #[cfg_attr(feature = "rkyv", rkyv(with = Skip))]
    pub trace_context: TraceContext,
}

impl QueuedTask {
    /// Create a new queued task
    pub fn new(descriptor: TaskDescriptor) -> Self {
        Self {
            id: TaskIdentifier::new_v4(),
            state: QueuedTaskState::Queued,
            descriptor,
            created_at: get_current_time_millis(),
            trace_context: trace_context(),
        }
    }

    /// Set the parent span of the caller to that described in the trace context
    pub fn enter_parent_span(&self) {
        set_parent_span_from_context(&self.trace_context);
    }
}

/// The state of a queued task
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "rkyv", derive(Archive, RkyvSerialize, RkyvDeserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug), attr(allow(missing_docs))))]
pub enum QueuedTaskState {
    /// The task is waiting in the queue
    Queued,
    /// The task is running and has preempted the queue
    Preemptive,
    /// The task is being run
    ///
    /// The state is serialized to a string before being stored to give a better
    /// API serialization
    Running {
        /// The state description of the task
        state: String,
        /// Whether the task has committed or not
        committed: bool,
    },
    /// The task is completed
    Completed,
    /// The task failed
    Failed,
}

impl QueuedTaskState {
    /// Whether the task is running
    pub fn is_running(&self) -> bool {
        matches!(self, QueuedTaskState::Running { .. })
            || matches!(self, QueuedTaskState::Preemptive)
    }

    /// Whether the task is committed
    pub fn is_committed(&self) -> bool {
        matches!(self, QueuedTaskState::Running { committed: true, .. })
    }

    /// Get a human-readable description of the task state
    pub fn display_description(&self) -> String {
        match self {
            QueuedTaskState::Queued => "Queued".to_string(),
            QueuedTaskState::Preemptive => "Running".to_string(),
            QueuedTaskState::Running { state, .. } => state.clone(),
            QueuedTaskState::Completed => "Completed".to_string(),
            QueuedTaskState::Failed => "Failed".to_string(),
        }
    }
}

#[cfg(feature = "rkyv")]
impl ArchivedQueuedTaskState {
    /// Whether the task is running
    pub fn is_running(&self) -> bool {
        matches!(self, ArchivedQueuedTaskState::Running { .. })
            || matches!(self, ArchivedQueuedTaskState::Preemptive)
    }
}

/// A wrapper around the task descriptors
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "rkyv", derive(Archive, RkyvSerialize, RkyvDeserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
#[allow(clippy::large_enum_variant)]
pub enum TaskDescriptor {
    /// The task descriptor for the `NewAccount` task
    NewAccount(NewAccountTaskDescriptor),
    /// The task descriptor for the `NodeStartup` task
    NodeStartup(NodeStartupTaskDescriptor),
    /// The task descriptor for the `Deposit` task
    Deposit(DepositTaskDescriptor),
    /// The task descriptor for the `CreateBalance` task
    CreateBalance(CreateBalanceTaskDescriptor),
    /// The task descriptor for the `CreateOrder` task
    CreateOrder(CreateOrderTaskDescriptor),
    /// The task descriptor for the `CancelOrder` task
    CancelOrder(CancelOrderTaskDescriptor),
    /// The task descriptor for the `RefreshAccount` task
    RefreshAccount(RefreshAccountTaskDescriptor),
    /// The task descriptor for the `SettleInternalMatch` task
    SettleInternalMatch(SettleInternalMatchTaskDescriptor),
    /// The task descriptor for the `SettleExternalMatch` task
    SettleExternalMatch(SettleExternalMatchTaskDescriptor),
    /// The task descriptor for the `Withdraw` task
    Withdraw(WithdrawTaskDescriptor),
}

impl TaskDescriptor {
    /// Compute the task queue key for the task
    pub fn queue_key(&self) -> TaskQueueKey {
        match self {
            TaskDescriptor::NewAccount(task) => task.account_id,
            TaskDescriptor::NodeStartup(task) => task.id,
            TaskDescriptor::Deposit(task) => task.account_id,
            TaskDescriptor::CreateBalance(task) => task.account_id,
            TaskDescriptor::CreateOrder(task) => task.account_id,
            TaskDescriptor::CancelOrder(task) => task.account_id,
            TaskDescriptor::RefreshAccount(task) => task.account_id,
            TaskDescriptor::SettleInternalMatch(task) => task.account_id,
            TaskDescriptor::SettleExternalMatch(task) => task.account_id,
            TaskDescriptor::Withdraw(task) => task.account_id,
        }
    }

    /// Returns the IDs of the accounts affected by the task
    pub fn affected_accounts(&self) -> Vec<AccountId> {
        match self {
            TaskDescriptor::NewAccount(task) => vec![task.account_id],
            TaskDescriptor::NodeStartup(_) => vec![],
            TaskDescriptor::Deposit(task) => vec![task.account_id],
            TaskDescriptor::CreateBalance(task) => vec![task.account_id],
            TaskDescriptor::CreateOrder(task) => vec![task.account_id],
            TaskDescriptor::CancelOrder(task) => vec![task.account_id],
            TaskDescriptor::RefreshAccount(task) => vec![task.account_id],
            TaskDescriptor::SettleInternalMatch(task) => {
                vec![task.account_id, task.other_account_id]
            },
            TaskDescriptor::SettleExternalMatch(task) => vec![task.account_id],
            TaskDescriptor::Withdraw(task) => vec![task.account_id],
        }
    }

    /// Returns whether the task is an account task
    pub fn is_account_task(&self) -> bool {
        match self {
            TaskDescriptor::NewAccount(_) => true,
            TaskDescriptor::NodeStartup(_) => false,
            TaskDescriptor::Deposit(_) => true,
            TaskDescriptor::CreateBalance(_) => true,
            TaskDescriptor::CreateOrder(_) => true,
            TaskDescriptor::CancelOrder(_) => true,
            TaskDescriptor::RefreshAccount(_) => true,
            TaskDescriptor::SettleInternalMatch(_) => true,
            TaskDescriptor::SettleExternalMatch(_) => true,
            TaskDescriptor::Withdraw(_) => true,
        }
    }

    /// Get a human readable description of the task
    pub fn display_description(&self) -> String {
        match self {
            TaskDescriptor::NewAccount(_) => "New Account".to_string(),
            TaskDescriptor::NodeStartup(_) => "Node Startup".to_string(),
            TaskDescriptor::Deposit(_) => "Deposit".to_string(),
            TaskDescriptor::CreateBalance(_) => "Create Balance".to_string(),
            TaskDescriptor::CreateOrder(_) => "Create Order".to_string(),
            TaskDescriptor::CancelOrder(_) => "Cancel Order".to_string(),
            TaskDescriptor::RefreshAccount(_) => "Refresh Account".to_string(),
            TaskDescriptor::SettleInternalMatch(_) => "Settle Internal Match".to_string(),
            TaskDescriptor::SettleExternalMatch(_) => "Settle External Match".to_string(),
            TaskDescriptor::Withdraw(_) => "Withdraw".to_string(),
        }
    }
}
