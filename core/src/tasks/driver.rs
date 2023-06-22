//! The task driver drives a task forwards and executes partial retries
//! of certain critical sections of a task

use std::{collections::HashMap, fmt::Display, time::Duration};

use async_trait::async_trait;
use serde::Serialize;
use std::fmt::Debug;
use tokio::{
    runtime::{Builder as TokioRuntimeBuilder, Runtime as TokioRuntime},
    task::JoinHandle,
};
use tracing::log;
use uuid::Uuid;

use crate::{
    state::{new_async_shared, AsyncShared},
    system_bus::SystemBus,
    types::{task_topic_name, SystemBusMessage},
};

use super::{
    create_new_wallet::NewWalletTaskState, initialize_state::InitializeStateTaskState,
    lookup_wallet::LookupWalletTaskState, settle_match::SettleMatchTaskState,
    settle_match_internal::SettleMatchInternalTaskState, update_wallet::UpdateWalletTaskState,
};

/// A type alias for the identifier underlying a task
pub type TaskIdentifier = Uuid;

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
const TASK_DRIVER_N_RETRIES: usize = 20;

/// The task trait defines a sequence of largely async flows, each of which is possibly
/// unreliable and may need to be retried until completion or to some retry threshold
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
}

/// Defines a wrapper that allows state objects to be stored generically
#[derive(Clone, Debug, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(tag = "task_type", content = "state")]
pub enum StateWrapper {
    /// The state object for the relayer state initialization task
    InitializeState(InitializeStateTaskState),
    /// The state object for the deposit balance task
    UpdateWallet(UpdateWalletTaskState),
    /// The state object for the lookup wallet task
    LookupWallet(LookupWalletTaskState),
    /// The state object for the new wallet task
    NewWallet(NewWalletTaskState),
    /// The state object for the settle match task
    SettleMatch(SettleMatchTaskState),
    /// The state object for the settle match internal task
    SettleMatchInternal(SettleMatchInternalTaskState),
}

/// Drives tasks to completion
#[derive(Clone)]
pub struct TaskDriver {
    /// The set of open tasks
    open_tasks: AsyncShared<HashMap<Uuid, StateWrapper>>,
    /// The runtime to spawn tasks onto
    runtime: AsyncShared<TokioRuntime>,
    /// A reference to the system bus for sending pubsub updates
    system_bus: SystemBus<SystemBusMessage>,
}

impl TaskDriver {
    /// Constructor
    pub fn new(system_bus: SystemBus<SystemBusMessage>) -> Self {
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
            system_bus,
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
    pub async fn start_task<T: Task + 'static>(&self, task: T) -> (Uuid, JoinHandle<bool>) {
        // Add the task to the bookkeeping structure
        let task_id = Uuid::new_v4();
        {
            self.open_tasks
                .write()
                .await
                .insert(task_id, task.state().into());
        } // open_tasks lock released

        // Drive the task
        let self_clone = self.clone();
        let join_handle = self
            .runtime
            .read()
            .await
            .spawn(async move { self_clone.run_task_to_completion(task_id, task).await });

        (task_id, join_handle)
    }

    /// Run a task to completion
    async fn run_task_to_completion<T: Task>(&self, task_id: Uuid, mut task: T) -> bool {
        let task_name = task.name();

        // Run each step individually and update the state after each step
        'outer: while !task.completed() {
            // Take a step
            let mut retries = TASK_DRIVER_N_RETRIES;
            let mut curr_backoff = Duration::from_millis(INITIAL_BACKOFF_MS);

            while let Err(e) = task.step().await {
                log::error!("error executing task step: {e:?}");
                retries -= 1;

                if retries == 0 {
                    log::error!("retries exceeded... task failed");
                    break 'outer;
                }

                tokio::time::sleep(curr_backoff).await;
                log::info!("retrying task {task_id:?} from state: {}", task.state());
                curr_backoff *= BACKOFF_AMPLIFICATION_FACTOR;
                curr_backoff =
                    Duration::min(curr_backoff, Duration::from_millis(BACKOFF_CEILING_MS));
            }

            // Update the state in the registry
            let task_state = task.state();
            log::info!("task {task_name}({task_id:?}) transitioning to state {task_state}");

            {
                *self.open_tasks.write().await.get_mut(&task_id).unwrap() = task_state.into()
            } // open_tasks lock released

            // Publish the state to the system bus for listeners on this task
            self.system_bus.publish(
                task_topic_name(&task_id),
                SystemBusMessage::TaskStatusUpdate {
                    task_id,
                    state: Box::new(task.state().into()),
                },
            );
        }

        task.completed()
    }
}
