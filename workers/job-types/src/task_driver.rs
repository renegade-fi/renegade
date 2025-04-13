//! Job types for the task driver

use common::types::tasks::{QueuedTask, TaskIdentifier};
use crossbeam::channel::Sender as CrossbeamSender;
use tokio::sync::oneshot::{
    channel as oneshot_channel, Receiver as OneshotReceiver, Sender as OneshotSender,
};
use util::metered_channels::MeteredCrossbeamReceiver;

/// The name of the task driver queue, used to label queue length metrics
const TASK_DRIVER_QUEUE_NAME: &str = "task_driver";

/// The queue sender type to send jobs to the task driver
pub type TaskDriverQueue = CrossbeamSender<TaskDriverJob>;
/// The queue receiver type to receive jobs for the task driver
pub type TaskDriverReceiver = MeteredCrossbeamReceiver<TaskDriverJob>;
/// The sender type of a task notification channel
pub type TaskNotificationSender = OneshotSender<Result<(), String>>;
/// The receiver type of a task notification channel
pub type TaskNotificationReceiver = OneshotReceiver<Result<(), String>>;

/// Create a new task driver queue
pub fn new_task_driver_queue() -> (TaskDriverQueue, TaskDriverReceiver) {
    let (send, recv) = crossbeam::channel::unbounded();
    (send, MeteredCrossbeamReceiver::new(recv, TASK_DRIVER_QUEUE_NAME))
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
    Run {
        /// The task to run
        task: QueuedTask,
        /// The channel on which to notify the worker
        channel: Option<TaskNotificationSender>,
    },
    /// Request that the task driver notify a worker when a task is complete
    Notify {
        /// The task id to notify the worker about
        task_id: TaskIdentifier,
        /// The channel on which to notify the worker
        channel: TaskNotificationSender,
    },
}

impl TaskDriverJob {
    /// Create a new run job
    pub fn run(task: QueuedTask) -> Self {
        Self::Run { task, channel: None }
    }

    /// Create a new run job with a notification channel
    pub fn run_with_notification(task: QueuedTask) -> (Self, TaskNotificationReceiver) {
        let (sender, receiver) = oneshot_channel();
        (Self::Run { task, channel: Some(sender) }, receiver)
    }

    /// Create a new notification job
    pub fn new_notification(task_id: TaskIdentifier) -> (Self, TaskNotificationReceiver) {
        let (sender, receiver) = oneshot_channel();
        (Self::Notify { task_id, channel: sender }, receiver)
    }
}
