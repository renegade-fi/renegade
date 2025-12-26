//! Descriptors of tasks used to parameterize their execution
mod new_account;

pub use new_account::*;

use serde::{Deserialize, Serialize};
use util::{
    get_current_time_millis,
    telemetry::propagation::{TraceContext, set_parent_span_from_context, trace_context},
};
use uuid::Uuid;

use crate::types::AccountId;

/// A type alias for the identifier underlying a task
pub type TaskIdentifier = Uuid;
/// A type alias for the task queue key type, used to index tasks by shared
/// resource
pub type TaskQueueKey = Uuid;

/// A task in the task queue
#[derive(Clone, Debug, Serialize, Deserialize)]
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

/// A wrapper around the task descriptors
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum TaskDescriptor {
    /// The task descriptor for the `NewAccount` task
    NewAccount(NewAccountTaskDescriptor),
}

impl TaskDescriptor {
    /// Compute the task queue key for the task
    pub fn queue_key(&self) -> TaskQueueKey {
        match self {
            TaskDescriptor::NewAccount(task) => task.account_id,
        }
    }

    /// Returns the IDs of the wallets affected by the task
    pub fn affected_accounts(&self) -> Vec<AccountId> {
        match self {
            TaskDescriptor::NewAccount(task) => vec![task.account_id],
        }
    }

    /// Returns whether the task is a wallet task
    pub fn is_wallet_task(&self) -> bool {
        match self {
            TaskDescriptor::NewAccount(_) => true,
        }
    }

    /// Get a human readable description of the task
    pub fn display_description(&self) -> String {
        match self {
            TaskDescriptor::NewAccount(_) => "New Account".to_string(),
        }
    }
}
