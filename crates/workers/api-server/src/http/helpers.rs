//! Helper functions for the HTTP API

use std::time::Duration;

use job_types::task_driver::{TaskDriverQueue, new_task_notification};
use state::State;
use tokio::time::timeout;
use types_tasks::{TaskDescriptor, TaskIdentifier};

use crate::error::{ApiServerError, internal_error};

/// The timeout for awaiting a blocking task completion
const BLOCKING_TASK_TIMEOUT: Duration = Duration::from_secs(30);

/// Append a task to the task queue
///
/// If `blocking` is true, the function will await the task's completion
/// with a 30-second timeout.
pub async fn append_task(
    task: TaskDescriptor,
    blocking: bool,
    state: &State,
    task_queue: &TaskDriverQueue,
) -> Result<TaskIdentifier, ApiServerError> {
    let (tid, waiter) = state.append_task(task).await?;
    waiter.await?;

    if !blocking {
        return Ok(tid);
    }

    // Register for task completion notification and await with timeout
    let (rx, job) = new_task_notification(tid);
    task_queue.send(job).map_err(|e| internal_error(e.to_string()))?;

    match timeout(BLOCKING_TASK_TIMEOUT, rx).await {
        Ok(Ok(Ok(()))) => Ok(tid),
        Ok(Ok(Err(e))) => Err(internal_error(e)),
        Ok(Err(_recv_err)) => Err(internal_error("task notification channel closed unexpectedly")),
        Err(_timeout) => Err(internal_error("task timeout")),
    }
}
