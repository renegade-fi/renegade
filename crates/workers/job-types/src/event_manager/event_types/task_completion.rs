use serde::{Deserialize, Serialize};
use types_tasks::{HistoricalTask, TaskQueueKey};

/// A task completion event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskCompletionEvent {
    /// The key of the queue in which the task was executed
    pub task_queue_key: TaskQueueKey,
    /// The historical task that was completed
    pub historical_task: HistoricalTask,
}

impl TaskCompletionEvent {
    /// Creates a new task completion event
    pub fn new(task_queue_key: TaskQueueKey, historical_task: HistoricalTask) -> Self {
        Self { task_queue_key, historical_task }
    }

    /// Returns a human-readable description of the event
    pub fn describe(&self) -> String {
        "TaskCompletion".to_string()
    }
}
