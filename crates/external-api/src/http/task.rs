//! Defines API types for task status introspection

use common::types::tasks::{QueuedTask, TaskIdentifier};
use serde::{Deserialize, Serialize};

// ---------------
// | HTTP Routes |
// ---------------

/// Get the status of a task
pub const GET_TASK_STATUS_ROUTE: &str = "/v0/tasks/:task_id";
/// Get the task queue of a given wallet
pub const GET_TASK_QUEUE_ROUTE: &str = "/v0/task_queue/:wallet_id";
/// Get whether or not a given wallet's task queue is paused
pub const GET_TASK_QUEUE_PAUSED_ROUTE: &str = "/v0/task_queue/:wallet_id/is_paused";

// -------------
// | API Types |
// -------------

/// The task status for a given task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiTaskStatus {
    /// The ID of the task
    pub id: TaskIdentifier,
    /// The description of the task
    pub description: String,
    /// The status of the task
    pub state: String,
    /// Whether or not the task has already committed
    pub committed: bool,
}

/// The response type for a request to fetch task status
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetTaskStatusResponse {
    /// The status of the requested task
    pub status: ApiTaskStatus,
}

impl From<QueuedTask> for ApiTaskStatus {
    fn from(task: QueuedTask) -> Self {
        let state = task.state.display_description();
        let committed = task.state.is_committed();
        let description = task.descriptor.display_description();

        ApiTaskStatus { id: task.id, description, state, committed }
    }
}

/// The response type for a request to fetch all tasks on a wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskQueueListResponse {
    /// The list of tasks on a wallet
    pub tasks: Vec<ApiTaskStatus>,
}

/// The response type for a request to fetch whether a task queue is paused
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskQueuePausedResponse {
    /// Whether the task queue is paused
    pub is_paused: bool,
}
