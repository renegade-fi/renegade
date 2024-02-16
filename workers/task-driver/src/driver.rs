//! The task driver drives a task forwards and executes partial retries
//! of certain critical sections of a task

use std::{
    collections::{HashMap, HashSet},
    fmt::{Debug, Display},
    time::Duration,
};

use common::{
    new_shared,
    types::{
        tasks::TaskIdentifier,
        tasks::{QueuedTaskState, TaskDescriptor},
        wallet::WalletIdentifier,
    },
    Shared,
};
use futures::Future;
use job_types::task_driver::{TaskDriverJob, TaskDriverReceiver, TaskNotificationSender};
use serde::Serialize;
use state::State;
use tokio::runtime::{Builder as TokioRuntimeBuilder, Runtime as TokioRuntime};
use tracing::{error, info, info_span, instrument, warn, Instrument};

use crate::{
    error::TaskDriverError,
    running_task::RunnableTask,
    tasks::{
        create_new_wallet::{NewWalletTask, NewWalletTaskState},
        lookup_wallet::{LookupWalletTask, LookupWalletTaskState},
        settle_match::{SettleMatchTask, SettleMatchTaskState},
        settle_match_internal::{SettleMatchInternalTask, SettleMatchInternalTaskState},
        update_merkle_proof::{UpdateMerkleProofTask, UpdateMerkleProofTaskState},
        update_wallet::{UpdateWalletTask, UpdateWalletTaskState},
    },
    traits::{Task, TaskContext, TaskState},
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
    /// The set of currently running preemptive tasks
    ///
    /// These tasks are not stored in the state so we keep references to them
    /// here so that we can validate notification requests to them
    preemptive_tasks: Shared<HashSet<TaskIdentifier>>,
    /// The map of task notifications to send
    task_notifications: TaskNotificationMap,
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
            bus: config.system_bus.clone(),
        };

        Self {
            task_queue: config.task_queue,
            runtime,
            runtime_config: config.runtime_config,
            task_context,
            preemptive_tasks: new_shared(HashSet::new()),
            task_notifications: new_shared(HashMap::new()),
        }
    }

    // -----------
    // | Getters |
    // -----------

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

    /// Whether or not the given value is a valid preemptive task
    fn is_preemptive_task(&self, task_id: &TaskIdentifier) -> bool {
        self.preemptive_tasks.read().unwrap().contains(task_id)
    }

    // -----------
    // | Setters |
    // -----------

    /// Add a preemptive task to the set of running tasks
    fn add_preemptive_task(&self, task_id: TaskIdentifier) {
        self.preemptive_tasks.write().unwrap().insert(task_id);
    }

    // ------------------
    // | Execution Loop |
    // ------------------

    /// The execution loop of the `TaskExecutor`
    pub fn run(self) -> Result<(), TaskDriverError> {
        info!("starting task executor loop");
        let queue = &self.task_queue;

        loop {
            // Pull a job from the queue
            let job = queue.recv().map_err(|_| TaskDriverError::JobQueueClosed)?;
            let res = match job {
                TaskDriverJob::Run(task) => {
                    let fut = self.create_task_future(
                        false, // immediate
                        task.id,
                        task.descriptor,
                    );
                    self.runtime.spawn(
                        async move {
                            let res = fut.await;
                            if let Err(e) = res {
                                // TODO: May be able to remove this log & instrumentation below
                                error!("error running task: {e:?}");
                            }
                        }
                        .instrument(info_span!("task", task_id = %task.id)),
                    );

                    Ok(())
                },
                TaskDriverJob::RunImmediate { wallet_ids, task_id, task } => {
                    self.handle_run_immediate(wallet_ids, task_id, task)
                },
                TaskDriverJob::Notify { task_id, channel } => {
                    self.handle_notification_request(task_id, channel)
                },
            };

            if let Err(e) = res {
                error!("error handling task job: {e:?}");
            }
        }
    }

    /// Handle a notification request
    #[instrument(skip_all, err, fields(task_id = %task_id))]
    fn handle_notification_request(
        &self,
        task_id: TaskIdentifier,
        channel: TaskNotificationSender,
    ) -> Result<(), TaskDriverError> {
        // Check that the task exists
        if !self.state().contains_task(&task_id)? && !self.is_preemptive_task(&task_id) {
            warn!("got task notification request for non-existent task {task_id:?}");
            let _ = channel.send(Err(TASK_NOT_FOUND_ERROR.to_string()));
            return Ok(());
        }

        // Otherwise, index the channel for the task
        let mut task_notifications = self.task_notifications.write().unwrap();
        task_notifications.entry(task_id).or_default().push(channel);

        Ok(())
    }

    /// Handle a request to run a task immediately
    #[instrument(skip_all, err, fields(task_id = %task_id, wallet_ids = ?wallet_ids))]
    pub fn handle_run_immediate(
        &self,
        wallet_ids: Vec<WalletIdentifier>,
        task_id: TaskIdentifier,
        task: TaskDescriptor,
    ) -> Result<(), TaskDriverError> {
        // Check if any non-preemptable tasks conflict with this task before pausing
        for wallet_id in wallet_ids.iter() {
            if let Some(conflicting_task) = self.state().current_committed_task(wallet_id)? {
                error!(
                    "task preemption conflicts with committed task {conflicting_task:?}, aborting..."
                );

                return Ok(());
            }
        }

        // Pause the queues for the affected local wallets
        for wallet_id in wallet_ids.iter() {
            self.state().pause_task_queue(wallet_id)?;
        }

        // Start the task optimistically assuming that the queues are paused
        self.add_preemptive_task(task_id);
        let preemptive_tasks = self.preemptive_tasks.clone();

        let fut = self.create_task_future(true /* immediate */, task_id, task);
        let state = self.state().clone();
        self.runtime.spawn(
            async move {
                let res = fut.await;
                if let Err(e) = res {
                    error!("error running immediate task: {e:?}");
                }

                // Unpause the queues for the affected local wallets
                for wallet_id in wallet_ids.iter() {
                    state
                        .resume_task_queue(wallet_id)
                        .expect("error proposing wallet resume for {wallet_id}")
                        .await
                        .expect("error resuming wallet task queue for {wallet_id}");
                }

                // Remove from the preemptive tasks list
                preemptive_tasks.write().unwrap().remove(&task_id);
            }
            .instrument(info_span!("immediate_task", task_id = %task_id)),
        );

        Ok(())
    }

    // ------------------
    // | Task Execution |
    // ------------------

    /// Get the future for a task execution
    fn create_task_future(
        &self,
        immediate: bool,
        task_id: TaskIdentifier,
        descriptor: TaskDescriptor,
    ) -> impl Future<Output = Result<(), TaskDriverError>> {
        // Collect the arguments then spawn
        let ctx = self.task_context();
        let args = self.runtime_config;
        let task_notifications = self.task_notifications.clone();

        Self::start_task(immediate, task_id, descriptor, ctx, args, task_notifications)
    }

    /// Spawn a new task in the driver
    ///
    /// Returns the success of the task
    async fn start_task(
        immediate: bool,
        id: TaskIdentifier,
        task: TaskDescriptor,
        ctx: TaskContext,
        args: RuntimeArgs,
        notif: TaskNotificationMap,
    ) -> Result<(), TaskDriverError> {
        // Construct the task from the descriptor
        match task {
            TaskDescriptor::NewWallet(desc) => {
                Self::start_task_helper::<NewWalletTask>(immediate, id, desc, ctx, args, notif)
                    .await
            },
            TaskDescriptor::LookupWallet(desc) => {
                Self::start_task_helper::<LookupWalletTask>(immediate, id, desc, ctx, args, notif)
                    .await
            },
            TaskDescriptor::UpdateWallet(desc) => {
                Self::start_task_helper::<UpdateWalletTask>(immediate, id, desc, ctx, args, notif)
                    .await
            },
            TaskDescriptor::SettleMatch(desc) => {
                Self::start_task_helper::<SettleMatchTask>(immediate, id, desc, ctx, args, notif)
                    .await
            },
            TaskDescriptor::SettleMatchInternal(desc) => {
                Self::start_task_helper::<SettleMatchInternalTask>(
                    immediate, id, desc, ctx, args, notif,
                )
                .await
            },
            TaskDescriptor::UpdateMerkleProof(desc) => {
                Self::start_task_helper::<UpdateMerkleProofTask>(
                    immediate, id, desc, ctx, args, notif,
                )
                .await
            },
        }
    }

    /// A helper for the `start_task` method that has generics specified at call
    /// time
    async fn start_task_helper<T: Task>(
        immediate: bool,
        id: TaskIdentifier,
        descriptor: T::Descriptor,
        ctx: TaskContext,
        args: RuntimeArgs,
        notifications: TaskNotificationMap,
    ) -> Result<(), TaskDriverError> {
        // Create the task
        let mut task = RunnableTask::<T>::from_descriptor(immediate, id, descriptor, ctx).await?;

        // Run the task
        let res = Self::run_task_to_completion(&mut task, args).await;

        // Cleanup
        let cleanup_res = task.cleanup().await;
        let combined_res = res.and(cleanup_res);

        // Notify any listeners that the task has completed
        let str_res = combined_res.clone().map_err(|e| e.to_string());
        for sender in notifications.write().unwrap().remove(&id).unwrap_or_default() {
            let _ = sender.send(str_res.clone());
        }

        combined_res
    }

    /// Run a task to completion
    async fn run_task_to_completion<T: Task>(
        task: &mut RunnableTask<T>,
        args: RuntimeArgs,
    ) -> Result<(), TaskDriverError> {
        let id = task.id();
        let backoff_ceiling = Duration::from_millis(args.backoff_ceiling_ms);

        // Run each step individually and update the state after each step
        'outer: while !task.completed() {
            // Take a step
            let mut retries = args.n_retries;
            let mut curr_backoff = Duration::from_millis(args.initial_backoff_ms);

            while !task.step().await? {
                retries -= 1;
                if retries == 0 {
                    error!("retries exceeded... task failed");
                    break 'outer;
                }

                // Sleep the backoff time and retry
                tokio::time::sleep(curr_backoff).await;
                info!("retrying task {id:?} from state: {}", task.state());

                curr_backoff *= args.backoff_amplification_factor;
                curr_backoff = Duration::min(curr_backoff, backoff_ceiling);
            }
        }

        if task.completed() {
            Ok(())
        } else {
            Err(TaskDriverError::TaskFailed)
        }
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

impl StateWrapper {
    /// Whether the underlying state is committed or not
    pub fn committed(&self) -> bool {
        match self {
            StateWrapper::LookupWallet(state) => state.committed(),
            StateWrapper::NewWallet(state) => state.committed(),
            StateWrapper::SettleMatch(state) => state.committed(),
            StateWrapper::SettleMatchInternal(state) => state.committed(),
            StateWrapper::UpdateWallet(state) => state.committed(),
            StateWrapper::UpdateMerkleProof(state) => state.committed(),
        }
    }

    /// Whether or not this state commits the task, i.e. is the first state that
    /// for which `committed` is true
    pub fn is_committing(&self) -> bool {
        match self {
            StateWrapper::LookupWallet(state) => state == &LookupWalletTaskState::commit_point(),
            StateWrapper::NewWallet(state) => state == &NewWalletTaskState::commit_point(),
            StateWrapper::SettleMatch(state) => state == &SettleMatchTaskState::commit_point(),
            StateWrapper::SettleMatchInternal(state) => {
                state == &SettleMatchInternalTaskState::commit_point()
            },
            StateWrapper::UpdateWallet(state) => state == &UpdateWalletTaskState::commit_point(),
            StateWrapper::UpdateMerkleProof(state) => {
                state == &UpdateMerkleProofTaskState::commit_point()
            },
        }
    }
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
        let committed = value.committed();
        QueuedTaskState::Running { state, committed }
    }
}
