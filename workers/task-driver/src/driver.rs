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
        tasks::{QueuedTaskState, TaskDescriptor},
        wallet::WalletIdentifier,
    },
    Shared,
};
use job_types::task_driver::{TaskDriverJob, TaskDriverReceiver, TaskNotificationSender};
use serde::Serialize;
use state::State;
use tokio::runtime::Builder as TokioRuntimeBuilder;
use tracing::{error, info, instrument, warn};
use util::telemetry::helpers::backfill_trace_field;

use crate::{
    error::TaskDriverError,
    running_task::RunnableTask,
    tasks::{
        create_new_wallet::{NewWalletTask, NewWalletTaskState},
        lookup_wallet::{LookupWalletTask, LookupWalletTaskState},
        node_startup::{NodeStartupTask, NodeStartupTaskState},
        pay_offline_fee::{PayOfflineFeeTask, PayOfflineFeeTaskState},
        pay_relayer_fee::{PayRelayerFeeTask, PayRelayerFeeTaskState},
        redeem_fee::{RedeemFeeTask, RedeemFeeTaskState},
        refresh_wallet::{RefreshWalletTask, RefreshWalletTaskState},
        settle_match::{SettleMatchTask, SettleMatchTaskState},
        settle_match_internal::{SettleMatchInternalTask, SettleMatchInternalTaskState},
        update_merkle_proof::{UpdateMerkleProofTask, UpdateMerkleProofTaskState},
        update_wallet::{UpdateWalletTask, UpdateWalletTaskState},
    },
    traits::{Task, TaskContext, TaskState},
    worker::TaskDriverConfig,
};

#[cfg(feature = "task-metrics")]
use renegade_metrics::helpers::{decr_inflight_tasks, incr_completed_tasks, incr_inflight_tasks};

/// The amount to increase the backoff delay by every retry
const BACKOFF_AMPLIFICATION_FACTOR: u32 = 2;
/// The maximum to increase the backoff to in milliseconds
const BACKOFF_CEILING_MS: u64 = 30_000; // 30 seconds
/// The initial backoff time when retrying a task
const INITIAL_BACKOFF_MS: u64 = 100; // 100 milliseconds
/// The name of the threads backing the task driver
const TASK_DRIVER_THREAD_NAME: &str = "renegade-task-driver";
/// The number of times to retry a step in a task before propagating the error
const TASK_DRIVER_N_RETRIES: usize = 5;
/// The stack size to allocate for task driver threads
const DRIVER_THREAD_STACK_SIZE: usize = 5_000_000; // 5MB

/// Error message sent on a notification when a task is not found
const TASK_NOT_FOUND_ERROR: &str = "task not found";

// ---------------
// | Task Driver |
// ---------------

/// The type that indexes task notifications
type TaskNotificationMap = Shared<HashMap<TaskIdentifier, Vec<TaskNotificationSender>>>;

/// Drives tasks to completion
#[derive(Clone)]
pub struct TaskExecutor {
    /// The queue on which to receive tasks
    task_queue: TaskDriverReceiver,
    /// The runtime config, contains information on how tasks should be run
    runtime_config: RuntimeArgs,
    /// The task context passed to each task, used to inject dependencies
    /// into the task
    task_context: TaskContext,
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
}

impl Default for RuntimeArgs {
    fn default() -> Self {
        Self {
            backoff_amplification_factor: BACKOFF_AMPLIFICATION_FACTOR,
            backoff_ceiling_ms: BACKOFF_CEILING_MS,
            initial_backoff_ms: INITIAL_BACKOFF_MS,
            n_retries: TASK_DRIVER_N_RETRIES,
        }
    }
}

impl TaskExecutor {
    /// Constructor
    pub fn new(config: TaskDriverConfig) -> Self {
        let task_context = TaskContext {
            arbitrum_client: config.arbitrum_client,
            network_queue: config.network_queue,
            proof_queue: config.proof_queue,
            task_queue: config.task_queue_sender,
            state: config.state,
            bus: config.system_bus.clone(),
        };

        Self {
            task_queue: config.task_queue,
            runtime_config: config.runtime_config,
            task_context,
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

    // ------------------
    // | Execution Loop |
    // ------------------

    /// The execution loop of the `TaskExecutor`
    pub fn run(self) -> Result<(), TaskDriverError> {
        info!("starting task executor loop");
        let queue = &self.task_queue;
        // Build a runtime
        let runtime = TokioRuntimeBuilder::new_multi_thread()
            .enable_all()
            .thread_stack_size(DRIVER_THREAD_STACK_SIZE)
            .thread_name(TASK_DRIVER_THREAD_NAME)
            .build()
            .expect("error building task driver runtime");

        loop {
            // Pull a job from the queue
            let job = queue.recv().map_err(|_| TaskDriverError::JobQueueClosed)?;
            let this = self.clone();
            runtime.spawn(async move {
                if let Err(e) = this.handle_job(job).await {
                    error!("error handling job: {e:?}");
                }
            });
        }
    }

    /// Handle a job sent to the task driver
    async fn handle_job(&self, job: TaskDriverJob) -> Result<(), TaskDriverError> {
        match job {
            TaskDriverJob::Run(task) => {
                let affected_wallets = task.descriptor.affected_wallets();
                self.start_task(
                    false, // immediate
                    task.id,
                    task.descriptor,
                    affected_wallets,
                )
                .await
            },
            TaskDriverJob::RunImmediate { task_id, task, resp } => {
                self.handle_run_immediate(task_id, task, resp).await
            },
            TaskDriverJob::Notify { task_id, channel } => {
                self.handle_notification_request(task_id, channel).await
            },
        }
    }

    /// Handle a notification request
    #[instrument(skip_all, err, fields(task_id = %task_id))]
    async fn handle_notification_request(
        &self,
        task_id: TaskIdentifier,
        channel: TaskNotificationSender,
    ) -> Result<(), TaskDriverError> {
        // Check that the task exists
        if !self.state().contains_task(&task_id).await? {
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
    #[instrument(skip_all, err, fields(task_id = %task_id, affected_wallets))]
    async fn handle_run_immediate(
        &self,
        task_id: TaskIdentifier,
        task: TaskDescriptor,
        resp: Option<TaskNotificationSender>,
    ) -> Result<(), TaskDriverError> {
        let affected_wallets = task.affected_wallets();
        backfill_trace_field("affected_wallets", format!("{affected_wallets:?}"));

        // Check if any non-preemptable tasks conflict with this task before pausing
        for wallet_id in affected_wallets.iter() {
            if let Some(s) = self.preemption_conflict(wallet_id).await? {
                warn!("task preemption failed: {s}");
                if let Some(chan) = resp {
                    let _ = chan.send(Err(s));
                }

                return Ok(());
            }
        }

        self.start_preemptive_task(affected_wallets, task_id, task, resp).await
    }

    /// Check for any conflicting conditions that cannot be preempted
    ///
    /// Returns an error message describing the conflict, if one exists
    async fn preemption_conflict(
        &self,
        wallet_id: &WalletIdentifier,
    ) -> Result<Option<String>, TaskDriverError> {
        if let Some(conflicting_task) = self.state().current_committed_task(wallet_id).await? {
            return Ok(Some(format!(
                "task preemption conflicts with committed task {conflicting_task:?}, aborting..."
            )));
        }

        if self.state().is_queue_paused(wallet_id).await? {
            return Ok(Some("queue already paused, aborting...".to_string()));
        }

        Ok(None)
    }

    // ------------------
    // | Task Execution |
    // ------------------

    /// Start the given task, preempting the queues of the given wallets
    async fn start_preemptive_task(
        &self,
        affected_wallets: Vec<WalletIdentifier>,
        task_id: TaskIdentifier,
        task: TaskDescriptor,
        resp: Option<TaskNotificationSender>,
    ) -> Result<(), TaskDriverError> {
        // Pause the queues for the affected local wallets
        if !affected_wallets.is_empty() {
            let waiter = self
                .state()
                .pause_multiple_task_queues(affected_wallets.clone(), task_id, task.clone())
                .await?;
            waiter.await?;
        }

        let res = self.start_task(true /* immediate */, task_id, task, affected_wallets).await;
        if let Err(e) = &res {
            error!("error running immediate task: {e:?}");
        }

        // Notify the task creator that the task has completed
        if let Some(sender) = resp {
            let _ = sender.send(res.map_err(|e| e.to_string()));
        }

        Ok(())
    }

    /// Spawn a new task in the driver
    ///
    /// Returns the success of the task

    #[instrument(name = "task", skip_all, err, fields(
        task_id = %id,
        task = %task.display_description(),
        wallet_ids = ?task.affected_wallets(),
    ))]
    async fn start_task(
        &self,
        immediate: bool,
        id: TaskIdentifier,
        task: TaskDescriptor,
        affected_wallets: Vec<WalletIdentifier>,
    ) -> Result<(), TaskDriverError> {
        // Construct the task from the descriptor
        let res = match task {
            TaskDescriptor::NewWallet(desc) => {
                self.start_task_helper::<NewWalletTask>(immediate, id, desc, affected_wallets).await
            },
            TaskDescriptor::LookupWallet(desc) => {
                self.start_task_helper::<LookupWalletTask>(immediate, id, desc, affected_wallets)
                    .await
            },
            TaskDescriptor::RefreshWallet(desc) => {
                self.start_task_helper::<RefreshWalletTask>(immediate, id, desc, affected_wallets)
                    .await
            },
            TaskDescriptor::OfflineFee(desc) => {
                self.start_task_helper::<PayOfflineFeeTask>(immediate, id, desc, affected_wallets)
                    .await
            },
            TaskDescriptor::RelayerFee(desc) => {
                self.start_task_helper::<PayRelayerFeeTask>(immediate, id, desc, affected_wallets)
                    .await
            },
            TaskDescriptor::RedeemFee(desc) => {
                self.start_task_helper::<RedeemFeeTask>(immediate, id, desc, affected_wallets).await
            },
            TaskDescriptor::UpdateWallet(desc) => {
                self.start_task_helper::<UpdateWalletTask>(immediate, id, desc, affected_wallets)
                    .await
            },
            TaskDescriptor::SettleMatch(desc) => {
                self.start_task_helper::<SettleMatchTask>(immediate, id, desc, affected_wallets)
                    .await
            },
            TaskDescriptor::SettleMatchInternal(desc) => {
                self.start_task_helper::<SettleMatchInternalTask>(
                    immediate,
                    id,
                    desc,
                    affected_wallets,
                )
                .await
            },
            TaskDescriptor::UpdateMerkleProof(desc) => {
                self.start_task_helper::<UpdateMerkleProofTask>(
                    immediate,
                    id,
                    desc,
                    affected_wallets,
                )
                .await
            },
            TaskDescriptor::NodeStartup(desc) => {
                self.start_task_helper::<NodeStartupTask>(immediate, id, desc, affected_wallets)
                    .await
            },
        };

        // Notify any listeners that the task has completed
        let str_res = res.clone().map_err(|e| e.to_string());
        for sender in self.task_notifications.write().unwrap().remove(&id).unwrap_or_default() {
            let _ = sender.send(str_res.clone());
        }

        res
    }

    /// A helper for the `start_task` method that has generics specified at call
    /// time
    async fn start_task_helper<T: Task>(
        &self,
        immediate: bool,
        id: TaskIdentifier,
        descriptor: T::Descriptor,
        affected_wallets: Vec<WalletIdentifier>,
    ) -> Result<(), TaskDriverError> {
        // Collect the arguments then spawn
        let ctx = self.task_context();
        let args = self.runtime_config;

        // Create and run the task
        let task_res = RunnableTask::<T>::from_descriptor(immediate, id, descriptor, ctx).await;

        // If we fail to create the task, pop it from the queue so it isn't stuck there
        // in a pending state. For immediate tasks, this is handled by queue
        // resumption.
        if let Err(e) = task_res {
            error!("error creating task: {e:?}");
            if !immediate {
                let waiter = self.state().pop_task(id, false /* success */).await?;
                waiter.await?;
            }

            return Err(e);
        }

        let mut task = task_res.unwrap();

        #[cfg(feature = "task-metrics")]
        incr_inflight_tasks();

        let res = Self::run_task_to_completion(&mut task, args).await;

        #[cfg(feature = "task-metrics")]
        {
            decr_inflight_tasks(1.0);
            incr_completed_tasks();
        }

        // Cleanup
        let cleanup_res = task.cleanup(res.is_ok(), affected_wallets).await;
        res.and(cleanup_res)
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
    /// The state object for the refresh wallet task
    RefreshWallet(RefreshWalletTaskState),
    /// The state object for the new wallet task
    NewWallet(NewWalletTaskState),
    /// The state object for the pay protocol fee task
    PayOfflineFee(PayOfflineFeeTaskState),
    /// The state object for the pay relayer fee task
    PayRelayerFee(PayRelayerFeeTaskState),
    /// The state object for the redeem relayer fees task
    RedeemFee(RedeemFeeTaskState),
    /// The state object for the settle match task
    SettleMatch(SettleMatchTaskState),
    /// The state object for the settle match internal task
    SettleMatchInternal(SettleMatchInternalTaskState),
    /// The state object for the update Merkle proof task
    UpdateMerkleProof(UpdateMerkleProofTaskState),
    /// The state object for the update wallet task
    UpdateWallet(UpdateWalletTaskState),
    /// The state object for the node startup task
    NodeStartup(NodeStartupTaskState),
}

impl StateWrapper {
    /// Whether the underlying state is committed or not
    pub fn committed(&self) -> bool {
        match self {
            StateWrapper::LookupWallet(state) => state.committed(),
            StateWrapper::RefreshWallet(state) => state.committed(),
            StateWrapper::NewWallet(state) => state.committed(),
            StateWrapper::PayOfflineFee(state) => state.committed(),
            StateWrapper::PayRelayerFee(state) => state.committed(),
            StateWrapper::RedeemFee(state) => state.committed(),
            StateWrapper::SettleMatch(state) => state.committed(),
            StateWrapper::SettleMatchInternal(state) => state.committed(),
            StateWrapper::UpdateWallet(state) => state.committed(),
            StateWrapper::UpdateMerkleProof(state) => state.committed(),
            StateWrapper::NodeStartup(state) => state.committed(),
        }
    }

    /// Whether or not this state commits the task, i.e. is the first state that
    /// for which `committed` is true
    pub fn is_committing(&self) -> bool {
        match self {
            StateWrapper::LookupWallet(state) => state == &LookupWalletTaskState::commit_point(),
            StateWrapper::RefreshWallet(state) => state == &RefreshWalletTaskState::commit_point(),
            StateWrapper::NewWallet(state) => state == &NewWalletTaskState::commit_point(),
            StateWrapper::PayOfflineFee(state) => state == &PayOfflineFeeTaskState::commit_point(),
            StateWrapper::PayRelayerFee(state) => state == &PayRelayerFeeTaskState::commit_point(),
            StateWrapper::RedeemFee(state) => state == &RedeemFeeTaskState::commit_point(),
            StateWrapper::SettleMatch(state) => state == &SettleMatchTaskState::commit_point(),
            StateWrapper::SettleMatchInternal(state) => {
                state == &SettleMatchInternalTaskState::commit_point()
            },
            StateWrapper::UpdateWallet(state) => state == &UpdateWalletTaskState::commit_point(),
            StateWrapper::UpdateMerkleProof(state) => {
                state == &UpdateMerkleProofTaskState::commit_point()
            },
            StateWrapper::NodeStartup(state) => state == &NodeStartupTaskState::commit_point(),
        }
    }

    /// Whether the underlying state is completed or not
    pub fn completed(&self) -> bool {
        match self {
            StateWrapper::LookupWallet(state) => state.completed(),
            StateWrapper::RefreshWallet(state) => state.completed(),
            StateWrapper::NewWallet(state) => state.completed(),
            StateWrapper::PayOfflineFee(state) => state.completed(),
            StateWrapper::PayRelayerFee(state) => state.completed(),
            StateWrapper::RedeemFee(state) => state.completed(),
            StateWrapper::SettleMatch(state) => state.completed(),
            StateWrapper::SettleMatchInternal(state) => state.completed(),
            StateWrapper::UpdateWallet(state) => state.completed(),
            StateWrapper::UpdateMerkleProof(state) => state.completed(),
            StateWrapper::NodeStartup(state) => state.completed(),
        }
    }
}

impl Display for StateWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let out = match self {
            StateWrapper::LookupWallet(state) => state.to_string(),
            StateWrapper::RefreshWallet(state) => state.to_string(),
            StateWrapper::NewWallet(state) => state.to_string(),
            StateWrapper::PayOfflineFee(state) => state.to_string(),
            StateWrapper::PayRelayerFee(state) => state.to_string(),
            StateWrapper::RedeemFee(state) => state.to_string(),
            StateWrapper::SettleMatch(state) => state.to_string(),
            StateWrapper::SettleMatchInternal(state) => state.to_string(),
            StateWrapper::UpdateWallet(state) => state.to_string(),
            StateWrapper::UpdateMerkleProof(state) => state.to_string(),
            StateWrapper::NodeStartup(state) => state.to_string(),
        };
        write!(f, "{out}")
    }
}

impl From<StateWrapper> for QueuedTaskState {
    fn from(value: StateWrapper) -> Self {
        // Serialize the state into a string
        let description = value.to_string();
        let committed = value.committed();
        QueuedTaskState::Running { state: description, committed }
    }
}
