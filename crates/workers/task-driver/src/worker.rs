//! Defines the worker implementation for the task-driver

use std::thread::{self, JoinHandle};

use async_trait::async_trait;
use darkpool_client::DarkpoolClient;
use job_types::{
    event_manager::EventManagerQueue,
    matching_engine::MatchingEngineWorkerQueue,
    network_manager::NetworkManagerQueue,
    proof_manager::ProofManagerQueue,
    task_driver::{TaskDriverQueue, TaskDriverReceiver},
};
use state::State;
use system_bus::SystemBus;
use types_core::HmacKey;
use types_runtime::Worker;
use url::Url;
use util::DefaultOption;

use crate::{
    driver::{RuntimeArgs, TaskExecutor},
    error::TaskDriverError,
};

// ----------
// | Config |
// ----------

/// The configuration for the task driver
pub struct TaskDriverConfig {
    /// The runtime config of the task driver
    pub runtime_config: RuntimeArgs,
    /// The queue on which to receive tasks
    pub task_queue: TaskDriverReceiver,
    /// The sender to the task driver's queue
    ///
    /// For recursive job enqueues
    pub task_queue_sender: TaskDriverQueue,
    /// The darkpool client used by the system
    pub darkpool_client: DarkpoolClient,
    /// A sender to the network manager's work queue
    pub network_queue: NetworkManagerQueue,
    /// A sender to the proof manager's work queue
    pub proof_queue: ProofManagerQueue,
    /// A sender to the event manager's work queue
    pub event_queue: EventManagerQueue,
    /// A sender to the matching engine worker's work queue
    pub matching_engine_queue: MatchingEngineWorkerQueue,
    /// The system bus to publish task updates onto
    pub system_bus: SystemBus,
    /// A handle on the global state
    pub state: State,
    /// The indexer URL to use for the darkpool indexer API
    pub indexer_url: Url,
    /// The HMAC key for authenticating requests to the indexer API
    pub indexer_hmac_key: HmacKey,
}

impl TaskDriverConfig {
    /// Create a new config with default values
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task_queue: TaskDriverReceiver,
        task_queue_sender: TaskDriverQueue,
        darkpool_client: DarkpoolClient,
        network_queue: NetworkManagerQueue,
        proof_queue: ProofManagerQueue,
        event_queue: EventManagerQueue,
        matching_engine_queue: MatchingEngineWorkerQueue,
        system_bus: SystemBus,
        state: State,
        indexer_url: Url,
        indexer_hmac_key: HmacKey,
    ) -> Self {
        Self {
            runtime_config: Default::default(),
            task_queue,
            task_queue_sender,
            darkpool_client,
            network_queue,
            proof_queue,
            event_queue,
            matching_engine_queue,
            system_bus,
            state,
            indexer_url,
            indexer_hmac_key,
        }
    }
}

// ----------
// | Worker |
// ----------

/// The task driver, hold a handle to its underlying executor
pub struct TaskDriver {
    /// The underlying executor
    executor: DefaultOption<TaskExecutor>,
    /// The handle on the underlying executor
    handle: Option<JoinHandle<TaskDriverError>>,
}

#[async_trait]
impl Worker for TaskDriver {
    type Error = TaskDriverError;
    type WorkerConfig = TaskDriverConfig;

    fn name(&self) -> String {
        "task-driver".to_string()
    }

    async fn new(config: Self::WorkerConfig) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let executor = TaskExecutor::new(config);

        Ok(Self { executor: DefaultOption::new(Some(executor)), handle: None })
    }

    fn start(&mut self) -> Result<(), Self::Error> {
        // Spawn the executor
        let exec = self.executor.take().unwrap();
        let handle = thread::Builder::new()
            .name("task-executor".to_string())
            .spawn(move || exec.run().unwrap_err())
            .expect("error spawning task executor");
        self.handle = Some(handle);
        Ok(())
    }

    fn join(&mut self) -> Vec<JoinHandle<Self::Error>> {
        vec![self.handle.take().unwrap()]
    }

    fn is_recoverable(&self) -> bool {
        false
    }

    fn cleanup(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}
