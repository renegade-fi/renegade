//! Defines the worker implementation for the task-driver

use std::thread::{self, JoinHandle};

use async_trait::async_trait;
use common::{default_wrapper::DefaultOption, worker::Worker};
use darkpool_client::client::DarkpoolClient;
use external_api::bus_message::SystemBusMessage;
use job_types::{
    event_manager::EventManagerQueue,
    network_manager::NetworkManagerQueue,
    proof_manager::ProofManagerQueue,
    task_driver::{TaskDriverQueue, TaskDriverReceiver},
};
use state::State;
use system_bus::SystemBus;

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
    /// The system bus to publish task updates onto
    pub system_bus: SystemBus<SystemBusMessage>,
    /// A handle on the global state
    pub state: State,
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
        system_bus: SystemBus<SystemBusMessage>,
        state: State,
    ) -> Self {
        Self {
            runtime_config: Default::default(),
            task_queue,
            task_queue_sender,
            darkpool_client,
            network_queue,
            proof_queue,
            event_queue,
            system_bus,
            state,
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
