//! The task driver drives a task forwards and executes partial retries
//! of certain critical sections of a task

use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    time::Duration,
};

use common::{
    new_shared,
    types::{
        tasks::TaskIdentifier,
        tasks::{QueuedTask, QueuedTaskState, TaskDescriptor},
        wallet::WalletIdentifier,
    },
    Shared,
};
use external_api::bus_message::{task_topic_name, SystemBusMessage};
use job_types::task_driver::{TaskDriverJob, TaskDriverReceiver, TaskNotificationSender};
use serde::Serialize;
use state::State;
use system_bus::SystemBus;
use tokio::runtime::{Builder as TokioRuntimeBuilder, Runtime as TokioRuntime};
use tracing::log;
use util::err_str;

use crate::{
    error::TaskDriverError,
    tasks::{
        create_new_wallet::{NewWalletTask, NewWalletTaskState},
        lookup_wallet::{LookupWalletTask, LookupWalletTaskState},
        settle_match::{SettleMatchTask, SettleMatchTaskState},
        settle_match_internal::{SettleMatchInternalTask, SettleMatchInternalTaskState},
        update_merkle_proof::{UpdateMerkleProofTask, UpdateMerkleProofTaskState},
        update_wallet::{UpdateWalletTask, UpdateWalletTaskState},
    },
    traits::{Task, TaskContext, TaskError},
    worker::TaskDriverConfig,
};

/// The amount to increase the backoff delay by every retry
const BACKOFF_AMPLIFICATION_FACTOR: u32 = 2;
/// The maximum to increase the backoff to in milliseconds
const BACKOFF_CEILING_MS: u64 = 30_000; // 30 seconds
/// The initial backoff time when retrying a task
const INITIAL_BACKOFF_MS: u64 = 2000; // 2 seconds
/// The number of threads backing the tokio runtime
const TASK_DRIVER_N_THREADS: usize = 5;
/// The name of the threads backing the task driver
const TASK_DRIVER_THREAD_NAME: &str = "renegade-task-driver";
/// The number of times to retry a step in a task before propagating the error
const TASK_DRIVER_N_RETRIES: usize = 5;

/// Error message sent on a notification when a task is not found
const TASK_NOT_FOUND_ERROR: &str = "task not found";

// ---------------
// | Task Driver |
// ---------------

/// The type that indexes task notifications
type TaskNotificationMap = Shared<HashMap<TaskIdentifier, Vec<TaskNotificationSender>>>;

/// Drives tasks to completion
pub struct TaskExecutor {
    /// The queue on which to receive tasks
    task_queue: TaskDriverReceiver,
    /// The runtime to spawn tasks onto
    runtime: TokioRuntime,
    /// The runtime config, contains information on how tasks should be run
    runtime_config: RuntimeArgs,
    /// The task context passed to each task, used to inject dependencies
    /// into the task
    task_context: TaskContext,
    /// The map of task notifications to send
    task_notifications: TaskNotificationMap,
    /// The system bus to publish task updates onto
    system_bus: SystemBus<SystemBusMessage>,
}

/// The config of the runtime arguments
#[derive(Copy, Clone, Debug)]
pub struct RuntimeArgs {
    /// The backoff amplification factor
    ///
    /// I.e. the multiplicative increase in backoff timeout after a failed step
    pub backoff_amplification_factor: u32,
    /// The maximum backoff timeout in milliseconds
    pub backoff_ceiling_ms: u64,
    /// The initial backoff timeout in milliseconds
    pub initial_backoff_ms: u64,
    /// The number of retries to attempt before propagating an error
    pub n_retries: usize,
    /// The number of threads backing the tokio runtime
    pub n_threads: usize,
}

impl Default for RuntimeArgs {
    fn default() -> Self {
        Self {
            backoff_amplification_factor: BACKOFF_AMPLIFICATION_FACTOR,
            backoff_ceiling_ms: BACKOFF_CEILING_MS,
            initial_backoff_ms: INITIAL_BACKOFF_MS,
            n_retries: TASK_DRIVER_N_RETRIES,
            n_threads: TASK_DRIVER_N_THREADS,
        }
    }
}

impl TaskExecutor {
    /// Constructor
    pub fn new(config: TaskDriverConfig) -> Self {
        // Build a runtime
        let runtime = TokioRuntimeBuilder::new_multi_thread()
            .enable_all()
            .worker_threads(TASK_DRIVER_N_THREADS)
            .thread_name(TASK_DRIVER_THREAD_NAME)
            .build()
            .expect("error building task driver runtime");

        let task_context = TaskContext {
            arbitrum_client: config.arbitrum_client,
            network_queue: config.network_queue,
            proof_queue: config.proof_queue,
            state: config.state,
        };

        Self {
            task_queue: config.task_queue,
            runtime,
            runtime_config: config.runtime_config,
            task_context,
            task_notifications: new_shared(HashMap::new()),
            system_bus: config.system_bus,
        }
    }

    /// Construct a copy of the `TaskContext`
    ///
    /// This is the set of dependencies that the driver injects into its tasks
    fn task_context(&self) -> TaskContext {
        self.task_context.clone()
    }

    /// Get a reference to the global state
    fn state(&self) -> &State {
        &self.task_context.state
    }

    /// The execution loop of the `TaskExecutor`
    pub fn run(self) -> Result<(), TaskDriverError> {
        log::info!("starting task executor loop");
        let queue = &self.task_queue;

        loop {
            // Pull a job from the queue
            let job = queue.recv().map_err(|_| TaskDriverError::JobQueueClosed)?;
            match job {
                TaskDriverJob::Run(task) => {
                    let ctx = self.task_context();
                    let args = self.runtime_config;
                    let bus = self.system_bus.clone();
                    let state = self.task_context.state.clone();
                    let task_notifications = self.task_notifications.clone();

                    self.runtime.spawn(async move {
                        if let Err(e) =
                            Self::start_task(task, ctx, args, bus, state, task_notifications).await
                        {
                            log::error!("error running task: {e:?}");
                        }
                    });
                },
                TaskDriverJob::Notify { task_id, channel } => {
                    if let Err(e) = self.handle_notification_request(task_id, channel) {
                        log::error!("error handling notification request: {e:?}");
                    }
                },
            }
        }
    }

    /// Handle a notification request
    fn handle_notification_request(
        &self,
        task_id: TaskIdentifier,
        channel: TaskNotificationSender,
    ) -> Result<(), TaskDriverError> {
        // Check that the task exists
        if !self.state().contains_task(&task_id)? {
            log::warn!("got task notification request for non-existent task {task_id:?}");
            let _ = channel.send(Err(TASK_NOT_FOUND_ERROR.to_string()));
            return Ok(());
        }

        // Otherwise, index the channel for the task
        let mut task_notifications = self.task_notifications.write().unwrap();
        task_notifications.entry(task_id).or_default().push(channel);

        Ok(())
    }

    /// Spawn a new task in the driver
    ///
    /// Returns the success of the task
    pub async fn start_task(
        task: QueuedTask,
        ctx: TaskContext,
        args: RuntimeArgs,
        bus: SystemBus<SystemBusMessage>,
        state: State,
        task_notifications: TaskNotificationMap,
    ) -> Result<(), TaskDriverError> {
        // Construct the task from the descriptor
        let id = task.id;
        let wallet_id = state
            .get_task_wallet(&id)
            .map_err(err_str!(TaskDriverError::State))?
            .expect("task not associated with a wallet");

        let state_clone = state.clone();
        let res = match task.descriptor {
            TaskDescriptor::NewWallet(desc) => {
                let task = NewWalletTask::new(desc, ctx).await?;
                Self::run_task_to_completion(id, wallet_id, task, args, bus, state).await
            },
            TaskDescriptor::LookupWallet(desc) => {
                let task = LookupWalletTask::new(desc, ctx).await?;
                Self::run_task_to_completion(id, wallet_id, task, args, bus, state).await
            },
            TaskDescriptor::UpdateWallet(desc) => {
                let task = UpdateWalletTask::new(desc, ctx).await?;
                Self::run_task_to_completion(id, wallet_id, task, args, bus, state).await
            },
            TaskDescriptor::SettleMatch(desc) => {
                let task = SettleMatchTask::new(desc, ctx).await?;
                Self::run_task_to_completion(id, wallet_id, task, args, bus, state).await
            },
            TaskDescriptor::SettleMatchInternal(desc) => {
                let task = SettleMatchInternalTask::new(desc, ctx).await?;
                Self::run_task_to_completion(id, wallet_id, task, args, bus, state).await
            },
            TaskDescriptor::UpdateMerkleProof(desc) => {
                let task = UpdateMerkleProofTask::new(desc, ctx).await?;
                Self::run_task_to_completion(id, wallet_id, task, args, bus, state).await
            },
        };

        let return_val =
            if res { Ok(()) } else { Err(TaskDriverError::TaskError("task failed".to_string())) };

        // Notify any listeners that the task has completed
        let str_err = return_val.clone().map_err(|e| e.to_string());
        for sender in task_notifications.write().unwrap().remove(&id).unwrap_or_default() {
            let _ = sender.send(str_err.clone());
        }

        // Pop the task from the queue so that the next task may run
        state_clone.pop_wallet_task(&wallet_id)?.await?;
        return_val
    }

    /// Run a task to completion
    async fn run_task_to_completion<T: Task>(
        task_id: TaskIdentifier,
        wallet_id: WalletIdentifier,
        mut task: T,
        args: RuntimeArgs,
        bus: SystemBus<SystemBusMessage>,
        state: State,
    ) -> bool {
        let task_name = task.name();

        // Run each step individually and update the state after each step
        'outer: while !task.completed() {
            // Take a step
            let mut retries = args.n_retries;
            let mut curr_backoff = Duration::from_millis(args.initial_backoff_ms);

            while let Err(e) = task.step().await {
                log::error!("error executing task step: {e:?}");
                retries -= 1;

                if retries == 0 || !e.retryable() {
                    log::error!("retries exceeded... task failed");
                    break 'outer;
                }

                tokio::time::sleep(curr_backoff).await;
                log::info!("retrying task {task_id:?} from state: {}", task.state());
                curr_backoff *= args.backoff_amplification_factor;
                curr_backoff =
                    Duration::min(curr_backoff, Duration::from_millis(args.backoff_ceiling_ms));
            }

            // Update the state in the registry
            let task_state: StateWrapper = task.state().into();
            log::info!("task {task_name}({task_id:?}) transitioning to state {task_state}");
            if let Err(e) = state.transition_wallet_task(&wallet_id, task_state.into()) {
                log::warn!("error updating task state: {e:?}");
            }

            // Publish the state to the system bus for listeners on this task
            bus.publish(
                task_topic_name(&task_id),
                SystemBusMessage::TaskStatusUpdate { task_id, state: task.state().to_string() },
            );
        }

        if let Err(e) = task.cleanup().await {
            log::error!("error cleaning up task: {e:?}");
        }
        task.completed()
    }
}

// --------------------
// | State Management |
// --------------------

/// Defines a wrapper that allows state objects to be stored generically
#[derive(Clone, Debug, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(tag = "task_type", content = "state")]
pub enum StateWrapper {
    /// The state object for the lookup wallet task
    LookupWallet(LookupWalletTaskState),
    /// The state object for the new wallet task
    NewWallet(NewWalletTaskState),
    /// The state object for the settle match task
    SettleMatch(SettleMatchTaskState),
    /// The state object for the settle match internal task
    SettleMatchInternal(SettleMatchInternalTaskState),
    /// The state object for the update Merkle proof task
    UpdateMerkleProof(UpdateMerkleProofTaskState),
    /// The state object for the update wallet task
    UpdateWallet(UpdateWalletTaskState),
}

impl Display for StateWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let out = match self {
            StateWrapper::LookupWallet(state) => state.to_string(),
            StateWrapper::NewWallet(state) => state.to_string(),
            StateWrapper::SettleMatch(state) => state.to_string(),
            StateWrapper::SettleMatchInternal(state) => state.to_string(),
            StateWrapper::UpdateWallet(state) => state.to_string(),
            StateWrapper::UpdateMerkleProof(state) => state.to_string(),
        };
        write!(f, "{out}")
    }
}

impl From<StateWrapper> for QueuedTaskState {
    fn from(value: StateWrapper) -> Self {
        // Serialize the state into a string
        let state = serde_json::to_string(&value).expect("error serializing state");
        QueuedTaskState::Running { state }
    }
}
