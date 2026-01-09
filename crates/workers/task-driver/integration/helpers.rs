//! Helpers for `task-driver` integration tests

use eyre::Result;
use job_types::task_driver::new_task_notification;
use types_tasks::TaskDescriptor;

use crate::IntegrationTestArgs;

/// Await the queueing, execution, and completion of a task
pub(crate) async fn await_task(
    task: TaskDescriptor,
    test_args: &IntegrationTestArgs,
) -> Result<()> {
    let state = test_args.mock_node.state();

    // Wait for the task to be queued
    let (task_id, waiter) = state.append_task(task).await?;
    waiter.await?;

    let (rx, job) = new_task_notification(task_id);
    test_args.mock_node.send_task_job(job)?;

    rx.await.unwrap().map_err(|e| eyre::eyre!(e))
}
