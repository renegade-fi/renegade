//! Setup logic for the node

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
    // TODO: Implement node setup
    // // Start the node setup task and await its completion
    // let desc: TaskDescriptor =
    //     NodeStartupTaskDescriptor::new(config.gossip_warmup,
    // config.relayer_wallet_key()).into();

    // // Send the task to the task driver
    // let task = QueuedTask::new(desc);
    // let (job, rx) = TaskDriverJob::run_with_notification(task);
    // task_queue.send(job).map_err(|_|
    // CoordinatorError::setup(ERR_SENDING_STARTUP_TASK))?;

    // // Await the task driver to complete the task
    // rx.await.map_err(err_str!(CoordinatorError::Setup))?.map_err(err_str!
    // (CoordinatorError::Setup))

    Ok(())
}
