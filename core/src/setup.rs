//! Setup logic for the node

use common::types::tasks::{
    NodeStartupTaskDescriptor, QueuedTask, QueuedTaskState, TaskDescriptor, TaskIdentifier,
};
use config::RelayerConfig;
use job_types::task_driver::{TaskDriverJob, TaskDriverQueue};
use util::{err_str, get_current_time_millis};

use crate::error::CoordinatorError;

/// An error sending a task to the task driver
const ERR_SENDING_STARTUP_TASK: &str = "error sending startup task to task driver";

/// Run the setup logic for the relayer
pub async fn node_setup(
    config: &RelayerConfig,
    task_queue: TaskDriverQueue,
) -> Result<(), CoordinatorError> {
    // Start the node setup task and await its completion
    let needs_relayer_wallet = config.needs_relayer_wallet();
    println!("needs_relayer_wallet: {needs_relayer_wallet}");
    let desc: TaskDescriptor = NodeStartupTaskDescriptor::new(
        config.gossip_warmup,
        config.relayer_arbitrum_key(),
        needs_relayer_wallet,
    )
    .into();

    let tid = TaskIdentifier::new_v4();
    let queued_task = QueuedTask {
        id: tid,
        state: QueuedTaskState::Preemptive,
        descriptor: desc,
        created_at: get_current_time_millis(),
    };

    // Send the task to the task driver
    let (job, rx) = TaskDriverJob::run_with_notification(queued_task);
    task_queue.send(job).map_err(|_| CoordinatorError::setup(ERR_SENDING_STARTUP_TASK))?;

    // Await the task driver to complete the task
    rx.await.map_err(err_str!(CoordinatorError::Setup))?.map_err(err_str!(CoordinatorError::Setup))
}
