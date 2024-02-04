//! Job types for the task driver

use common::types::task_descriptors::QueuedTask;
use crossbeam::channel::{Receiver as CrossbeamReceiver, Sender as CrossbeamSender};

/// The queue sender type to send jobs to the task driver
pub type TaskDriverQueue = CrossbeamSender<TaskDriverJob>;
/// The queue receiver type to receive jobs for the task driver
pub type TaskDriverReceiver = CrossbeamReceiver<TaskDriverJob>;

/// Create a new task driver queue
pub fn new_task_driver_queue() -> (TaskDriverQueue, TaskDriverReceiver) {
    crossbeam::channel::unbounded()
}

/// The job type for the task driver
#[derive(Debug, Clone)]
pub enum TaskDriverJob {
    /// Run a task
    Run(QueuedTask),
}
