//! Setup logic for the node
//!
//! TODO(@joey): This module will eventually become a dedicated task, for now
//! this is sufficient

use common::types::tasks::{NodeStartupTaskDescriptor, TaskDescriptor};
use config::RelayerConfig;
use job_types::task_driver::{TaskDriverJob, TaskDriverQueue};
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
    let desc: TaskDescriptor =
        NodeStartupTaskDescriptor::new(config.gossip_warmup, config.relayer_arbitrum_key()).into();
    let (job, rx) = TaskDriverJob::new_immediate_with_notification(desc);
    task_queue
        .send(job)
        .map_err(|_| CoordinatorError::Setup(ERR_SENDING_STARTUP_TASK.to_string()))?;

    rx.await.map_err(err_str!(CoordinatorError::Setup))?.map_err(err_str!(CoordinatorError::Setup))
}
