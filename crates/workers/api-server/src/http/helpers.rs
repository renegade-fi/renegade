//! Helper functions for the HTTP API

use state::State;
use types_tasks::{TaskDescriptor, TaskIdentifier};

use crate::error::ApiServerError;

/// Append a task to the state
pub async fn append_task(
    task: TaskDescriptor,
    state: &State,
) -> Result<TaskIdentifier, ApiServerError> {
    let (tid, waiter) = state.append_task(task).await?;
    waiter.await?;
    Ok(tid)
}
