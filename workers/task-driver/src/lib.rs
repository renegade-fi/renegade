//! Groups together long-running async tasks for best discoverability
//!
//! Examples of such tasks are creating a new wallet; which requires the
//! node to prove `VALID NEW WALLET`, submit the wallet on-chain, wait for
//! transaction success, and then prove `VALID COMMITMENTS`

#![allow(incomplete_features)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![feature(let_chains)]
#![feature(iter_advance_by)]

pub mod driver;
pub mod error;
mod running_task;
pub mod simulation;
pub mod state_migration;
pub mod task_state;
pub mod tasks;
pub mod traits;
pub(crate) mod utils;
pub mod worker;

use ::state::State;
use common::types::tasks::TaskDescriptor;
use job_types::task_driver::{TaskDriverQueue, new_task_notification};

/// A helper to enqueue a task and await its completion
/// Await the queueing, execution, and completion of a task
pub async fn await_task(
    task: TaskDescriptor,
    state: &State,
    task_queue: TaskDriverQueue,
) -> Result<(), String> {
    // Wait for the task to be queued
    let (task_id, waiter) = state.append_task(task).await?;
    waiter.await?;

    let (rx, job) = new_task_notification(task_id);
    task_queue.send(job).unwrap();

    rx.await.unwrap()
}
