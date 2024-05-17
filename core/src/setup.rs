//! Setup logic for the node
//!
//! TODO(@joey): This module will eventually become a dedicated task, for now
//! this is sufficient

use std::time::Duration;

use common::types::tasks::NodeStartupTaskDescriptor;
use config::RelayerConfig;
use job_types::task_driver::{new_task_notification, TaskDriverJob, TaskDriverQueue};
use util::err_str;

use crate::error::CoordinatorError;

/// An error sending a task to the task driver
const ERR_SENDING_STARTUP_TASK: &str = "error sending startup task to task driver";

/// Run the setup logic for the relayer
pub async fn node_setup(
    config: &RelayerConfig,
    task_queue: TaskDriverQueue,
) -> Result<(), CoordinatorError> {
    // Start the node setup task and await its completion
    let desc = NodeStartupTaskDescriptor::new(config.gossip_warmup, &config.arbitrum_private_key);
    let id = desc.id;
    task_queue
        .send(TaskDriverJob::RunImmediate { task_id: id, wallet_ids: vec![], task: desc.into() })
        .map_err(|_| CoordinatorError::Setup(ERR_SENDING_STARTUP_TASK.to_string()))?;

    // Wait for the task driver to index the task then request a notification
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (recv, job) = new_task_notification(id);
    task_queue
        .send(job)
        .map_err(|_| CoordinatorError::Setup(ERR_SENDING_STARTUP_TASK.to_string()))?;
    recv.await.unwrap().map_err(err_str!(CoordinatorError::Setup))
}
