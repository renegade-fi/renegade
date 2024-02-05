//! Defines the worker implementation for the task-driver

use std::thread::{self, JoinHandle};

use arbitrum_client::client::ArbitrumClient;
use common::{default_wrapper::DefaultOption, worker::Worker};
use external_api::bus_message::SystemBusMessage;
use job_types::{
    network_manager::NetworkManagerQueue, proof_manager::ProofManagerQueue,
    task_driver::TaskDriverReceiver,
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
    /// The arbitrum client used by the system
    pub arbitrum_client: ArbitrumClient,
    /// A sender to the network manager's work queue
    pub network_queue: NetworkManagerQueue,
    /// A sender to the proof manager's work queue
    pub proof_queue: ProofManagerQueue,
    /// The system bus to publish task updates onto
    pub system_bus: SystemBus<SystemBusMessage>,
    /// A handle on the global state
    pub state: State,
}

impl TaskDriverConfig {
    /// Create a new config with default values
    pub fn new(
        task_queue: TaskDriverReceiver,
        arbitrum_client: ArbitrumClient,
        network_queue: NetworkManagerQueue,
        proof_queue: ProofManagerQueue,
        system_bus: SystemBus<SystemBusMessage>,
        state: State,
    ) -> Self {
        Self {
            runtime_config: Default::default(),
            task_queue,
            arbitrum_client,
            network_queue,
            proof_queue,
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

impl Worker for TaskDriver {
    type Error = TaskDriverError;
    type WorkerConfig = TaskDriverConfig;

    fn name(&self) -> String {
        "task-driver".to_string()
    }

    fn new(config: Self::WorkerConfig) -> Result<Self, Self::Error>
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
