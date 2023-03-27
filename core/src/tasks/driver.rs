//! The task driver drives a task forwards and executes partial retries
//! of certain critical sections of a task

use std::{collections::HashMap, fmt::Display};

use async_trait::async_trait;
use serde::Serialize;
use std::fmt::Debug;
use tokio::runtime::{Builder as TokioRuntimeBuilder, Runtime as TokioRuntime};
use tracing::log;
use uuid::Uuid;

use crate::state::{new_async_shared, AsyncShared};

use super::create_new_wallet::NewWalletTaskState;

/// A type alias for the identifier underlying a task
pub type TaskIdentifier = Uuid;

/// The number of threads backing the tokio runtime
const TASK_DRIVER_N_THREADS: usize = 1;
/// The name of the threads backing the task driver
const TASK_DRIVER_THREAD_NAME: &str = "renegade-task-driver";
/// The number of times to retry a step in a task before propagating the error
const TASK_DRIVER_N_RETRIES: usize = 5;

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
pub enum StateWrapper {
    /// The state object for the new wallet task
    NewWallet(NewWalletTaskState),
}

/// Drives tasks to completion
#[derive(Clone)]
pub struct TaskDriver {
    /// The set of open tasks
    open_tasks: AsyncShared<HashMap<Uuid, StateWrapper>>,
    /// The runtime to spawn tasks onto
    runtime: AsyncShared<TokioRuntime>,
}

impl TaskDriver {
    /// Constructor
    pub fn new() -> Self {
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
        }
    }

    /// Spawn a new task in the driver
    ///
    /// Returns the ID of the task being spawned
    pub async fn run<T: Task + 'static>(&self, task: T) -> Uuid {
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
        self.runtime.read().await.spawn(async move {
            self_clone.run_task_to_completion(task_id, task).await;
        });

        task_id
    }

    /// Run a task to completion
    async fn run_task_to_completion<T: Task>(&self, task_id: Uuid, mut task: T) {
        let task_name = task.name();

        // Run each step individually and update the state after each step
        'outer: while !task.completed() {
            // Take a step
            let mut retries = TASK_DRIVER_N_RETRIES;
            while let Err(e) = task.step().await {
                log::error!("error executing task step: {e:?}");
                retries -= 1;

                if retries == 0 {
                    log::error!("retries exceeded... task failed");
                    break 'outer;
                }
            }

            // Update the state in the registry
            let task_state = task.state();
            log::info!("task {task_name} transitioning to state {task_state}");

            {
                *self.open_tasks.write().await.get_mut(&task_id).unwrap() = task_state.into()
            } // open_tasks lock released
        }
    }
}
