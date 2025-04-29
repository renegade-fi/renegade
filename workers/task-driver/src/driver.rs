//! The task driver drives a task forwards and executes partial retries
//! of certain critical sections of a task

use std::{collections::HashMap, fmt::Debug, time::Duration};

use common::types::{tasks::TaskDescriptor, tasks::TaskIdentifier, wallet::WalletIdentifier};
use job_types::task_driver::{TaskDriverJob, TaskDriverReceiver, TaskNotificationSender};
use state::State;
use tokio::runtime::Builder as TokioRuntimeBuilder;
use tracing::{error, info, instrument, warn};
use util::concurrency::{new_shared, Shared};

use crate::{
    error::TaskDriverError,
    running_task::RunnableTask,
    tasks::{
        create_new_wallet::NewWalletTask, lookup_wallet::LookupWalletTask,
        node_startup::NodeStartupTask, pay_offline_fee::PayOfflineFeeTask,
        pay_relayer_fee::PayRelayerFeeTask, redeem_fee::RedeemFeeTask,
        refresh_wallet::RefreshWalletTask,
        settle_malleable_external_match::SettleMalleableExternalMatchTask,
        settle_match::SettleMatchTask, settle_match_external::SettleMatchExternalTask,
        settle_match_internal::SettleMatchInternalTask, update_merkle_proof::UpdateMerkleProofTask,
        update_wallet::UpdateWalletTask,
    },
    traits::{Task, TaskContext},
    worker::TaskDriverConfig,
};

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
const DRIVER_THREAD_STACK_SIZE: usize = 50_000_000; // 50MB

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
            darkpool_client: config.darkpool_client,
            network_queue: config.network_queue,
            proof_queue: config.proof_queue,
            event_queue: config.event_queue,
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
            TaskDriverJob::Run { task, channel } => {
                let affected_wallets = task.descriptor.affected_wallets();
                self.start_task(
                    false, // immediate
                    task.id,
                    task.descriptor,
                    affected_wallets,
                    channel,
                )
                .await
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

    // ------------------
    // | Task Execution |
    // ------------------

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
        channel: Option<TaskNotificationSender>,
    ) -> Result<(), TaskDriverError> {
        // Register the notification if one was requested
        if let Some(c) = channel {
            let mut notifications_locked = self.task_notifications.write().expect("poisoned");
            notifications_locked.entry(id).or_default().push(c);
        }

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
            TaskDescriptor::SettleExternalMatch(desc) => {
                self.start_task_helper::<SettleMatchExternalTask>(
                    immediate,
                    id,
                    desc,
                    affected_wallets,
                )
                .await
            },
            TaskDescriptor::SettleMalleableExternalMatch(desc) => {
                self.start_task_helper::<SettleMalleableExternalMatchTask>(
                    immediate,
                    id,
                    desc,
                    affected_wallets,
                )
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
            let waiter = self.state().pop_task(id, false /* success */).await?;
            waiter.await?;

            return Err(e);
        }

        let mut task = task_res.unwrap();
        let res = Self::run_task_to_completion(&mut task, args).await;

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
