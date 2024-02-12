//! Defines API types for task status introspection

use common::types::tasks::{QueuedTask, QueuedTaskState, TaskIdentifier};
use serde::Serialize;

/// The response type for a request to fetch task status
#[derive(Clone, Debug, Serialize)]
pub struct GetTaskStatusResponse {
    /// The status of the requested task
    pub status: String,
}

/// A type encapsulating status information for a task
#[derive(Clone, Debug, Serialize)]
pub struct TaskStatus {
    /// The ID of the task
    pub id: TaskIdentifier,
    /// The status of the task
    pub status: String,
    /// Whether or not the task has already committed
    pub committed: bool,
}

impl From<QueuedTask> for TaskStatus {
    fn from(task: QueuedTask) -> Self {
        let (status, committed) = match task.state {
            QueuedTaskState::Queued => ("queued".to_string(), false),
            QueuedTaskState::Running { state, committed } => (state, committed),
        };

        TaskStatus { id: task.id, status, committed }
    }
}

/// The response type for a request to fetch all tasks on a wallet
#[derive(Clone, Debug, Serialize)]
pub struct TaskQueueListResponse {
    /// The list of tasks on a wallet
    pub tasks: Vec<TaskStatus>,
}
