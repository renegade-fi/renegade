//! The task driver drives a task forwards and executes partial retries
//! of certain critical sections of a task

use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    time::Duration,
};

use async_trait::async_trait;
use common::{new_async_shared, types::tasks::TaskIdentifier, AsyncShared};
use external_api::bus_message::{task_topic_name, SystemBusMessage};
use serde::Serialize;
use system_bus::SystemBus;
use tokio::{
    runtime::{Builder as TokioRuntimeBuilder, Runtime as TokioRuntime},
    task::JoinHandle,
};
use tracing::log;
use uuid::Uuid;

use crate::{
    create_new_wallet::NewWalletTaskState, lookup_wallet::LookupWalletTaskState,
    settle_match::SettleMatchTaskState, settle_match_internal::SettleMatchInternalTaskState,
    update_merkle_proof::UpdateMerkleProofTaskState, update_wallet::UpdateWalletTaskState,
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
///
/// TODO: This is high for now, bring this down as Starknet stabilizes
const TASK_DRIVER_N_RETRIES: usize = 5;

// ----------
// | Config |
// ----------

/// The configuration for the task driver
#[derive(Clone)]
pub struct TaskDriverConfig {
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
    /// The system bus to publish task updates onto
    pub system_bus: SystemBus<SystemBusMessage>,
}

impl TaskDriverConfig {
    /// Constructor
    pub fn default_with_bus(system_bus: SystemBus<SystemBusMessage>) -> Self {
        Self {
            backoff_amplification_factor: BACKOFF_AMPLIFICATION_FACTOR,
            backoff_ceiling_ms: BACKOFF_CEILING_MS,
            initial_backoff_ms: INITIAL_BACKOFF_MS,
            n_retries: TASK_DRIVER_N_RETRIES,
            n_threads: TASK_DRIVER_N_THREADS,
            system_bus,
        }
    }
}

// ------------------
// | Task and State |
// ------------------

/// The task trait defines a sequence of largely async flows, each of which is
/// possibly unreliable and may need to be retried until completion or to some
/// retry threshold
#[async_trait]
pub trait Task: Send {
    /// The state type of the task, used for task introspection
    type State: Debug + Display + Send + Serialize + Into<StateWrapper>;
    /// The error type that the task may give
    type Error: Send + Debug;

    /// Get the current state of the task
    fn state(&self) -> Self::State;
    /// Whether or not the task is completed
    fn completed(&self) -> bool;
    /// Get a displayable name for the task
    fn name(&self) -> String;
    /// Take a step in the task, steps should represent largely async behavior
    async fn step(&mut self) -> Result<(), Self::Error>;
    /// A cleanup step that is run in the event of a task failure
    async fn cleanup(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

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

// ---------------
// | Task Driver |
// ---------------

/// Drives tasks to completion
#[derive(Clone)]
pub struct TaskDriver {
    /// The set of open tasks
    open_tasks: AsyncShared<HashMap<TaskIdentifier, StateWrapper>>,
    /// The runtime to spawn tasks onto
    runtime: AsyncShared<TokioRuntime>,
    /// The task driver's config
    config: TaskDriverConfig,
}

impl TaskDriver {
    /// Constructor
    pub fn new(config: TaskDriverConfig) -> Self {
        // Build a runtime
        let runtime = TokioRuntimeBuilder::new_multi_thread()
            .enable_all()
            .worker_threads(TASK_DRIVER_N_THREADS)
            .thread_name(TASK_DRIVER_THREAD_NAME)
            .build()
            .expect("error building task driver runtime");

        Self {
            open_tasks: new_async_shared(HashMap::new()),
            runtime: new_async_shared(runtime),
            config,
        }
    }

    /// Returns whether the given task ID is valid
    pub async fn contains_task(&self, task_id: &TaskIdentifier) -> bool {
        self.open_tasks.read().await.contains_key(task_id)
    }

    /// Fetch the status of the requested task
    pub async fn get_task_state(&self, task_id: &TaskIdentifier) -> Option<StateWrapper> {
        self.open_tasks.read().await.get(task_id).cloned()
    }

    /// Spawn a new task in the driver
    ///
    /// Returns the ID of the task being spawned
    pub async fn start_task<T: Task + 'static>(
        &self,
        task: T,
    ) -> (TaskIdentifier, JoinHandle<bool>) {
        // Add the task to the bookkeeping structure
        let task_id = Uuid::new_v4();
        {
            self.open_tasks.write().await.insert(task_id, task.state().into());
        } // open_tasks lock released

        // Drive the task
        let self_clone = self.clone();
        #[allow(clippy::redundant_async_block)]
        let join_handle = self
            .runtime
            .read()
            .await
            .spawn(async move { self_clone.run_task_to_completion(task_id, task).await });

        (task_id, join_handle)
    }

    /// Run a task to completion
    async fn run_task_to_completion<T: Task>(&self, task_id: Uuid, mut task: T) -> bool {
        let config = &self.config;
        let task_name = task.name();

        // Run each step individually and update the state after each step
        'outer: while !task.completed() {
            // Take a step
            let mut retries = config.n_retries;
            let mut curr_backoff = Duration::from_millis(config.initial_backoff_ms);

            while let Err(e) = task.step().await {
                log::error!("error executing task step: {e:?}");
                retries -= 1;

                if retries == 0 {
                    log::error!("retries exceeded... task failed");

                    break 'outer;
                }

                tokio::time::sleep(curr_backoff).await;
                log::info!("retrying task {task_id:?} from state: {}", task.state());
                curr_backoff *= config.backoff_amplification_factor;
                curr_backoff =
                    Duration::min(curr_backoff, Duration::from_millis(config.backoff_ceiling_ms));
            }

            // Update the state in the registry
            let task_state = task.state();
            log::info!("task {task_name}({task_id:?}) transitioning to state {task_state}");

            {
                *self.open_tasks.write().await.get_mut(&task_id).unwrap() = task_state.into()
            } // open_tasks lock released

            // Publish the state to the system bus for listeners on this task
            self.config.system_bus.publish(
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
