//! Job types for the task driver

use common::types::{
    tasks::{QueuedTask, TaskDescriptor, TaskIdentifier},
    wallet::WalletIdentifier,
};
use crossbeam::channel::{Receiver as CrossbeamReceiver, Sender as CrossbeamSender};
use tokio::sync::oneshot::{
    channel as oneshot_channel, Receiver as OneshotReceiver, Sender as OneshotSender,
};

/// The queue sender type to send jobs to the task driver
pub type TaskDriverQueue = CrossbeamSender<TaskDriverJob>;
/// The queue receiver type to receive jobs for the task driver
pub type TaskDriverReceiver = CrossbeamReceiver<TaskDriverJob>;
/// The sender type of a task notification channel
pub type TaskNotificationSender = OneshotSender<Result<(), String>>;
/// The receiver type of a task notification channel
pub type TaskNotificationReceiver = OneshotReceiver<Result<(), String>>;

/// Create a new task driver queue
pub fn new_task_driver_queue() -> (TaskDriverQueue, TaskDriverReceiver) {
    crossbeam::channel::unbounded()
}

/// Create a new notification channel and job for the task driver
pub fn new_task_notification(task_id: TaskIdentifier) -> (TaskNotificationReceiver, TaskDriverJob) {
    let (sender, receiver) = oneshot_channel();
    (receiver, TaskDriverJob::Notify { task_id, channel: sender })
}

/// The job type for the task driver
#[derive(Debug)]
pub enum TaskDriverJob {
    /// Run a task
    Run(QueuedTask),
    /// Run a task immediately, bypassing the task queue
    ///
    /// This is used for tasks which need immediate settlement, e.g. matches
    ///
    /// Other tasks on a shared wallet will be preempted and the queue paused
    RunImmediate {
        /// The ID to assign the task
        task_id: TaskIdentifier,
        /// The wallet(s) that this task modifies
        wallet_ids: Vec<WalletIdentifier>,
        /// The task to run
        task: TaskDescriptor,
    },
    /// Request that the task driver notify a worker when a task is complete
    Notify {
        /// The task id to notify the worker about
        task_id: TaskIdentifier,
        /// The channel on which to notify the worker
        channel: TaskNotificationSender,
    },
}
