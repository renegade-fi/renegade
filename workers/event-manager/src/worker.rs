//! Defines the worker implementation for the event manager

use std::thread::{Builder, JoinHandle};

use async_trait::async_trait;
use common::{
    types::{CancelChannel, chain::Chain},
    worker::Worker,
};
use job_types::event_manager::EventManagerReceiver;
use tokio::runtime::Builder as RuntimeBuilder;
use tracing::info;
use url::Url;
use util::err_str;

use crate::{
    error::EventManagerError,
    manager::{EventManager, EventManagerExecutor},
};

// -------------
// | Constants |
// -------------

/// The number of threads to use for the event manager.
///
/// We only need one thread as no parallel tasks are spawned
/// by the event manager.
const EVENT_MANAGER_N_THREADS: usize = 1;

// ----------
// | Config |
// ----------

/// The configuration for the event manager
pub struct EventManagerConfig {
    /// The URL to export relayer events to
    pub event_export_url: Option<Url>,
    /// The queue on which to receive events
    pub event_queue: EventManagerReceiver,
    /// The chain for which the relayer is configured
    pub chain: Chain,
    /// The channel on which the coordinator may mandate that the
    /// event manager cancel its execution
    pub cancel_channel: CancelChannel,
}

#[async_trait]
impl Worker for EventManager {
    type WorkerConfig = EventManagerConfig;
    type Error = EventManagerError;

    async fn new(config: Self::WorkerConfig) -> Result<Self, Self::Error> {
        let executor = EventManagerExecutor::new(config);
        Ok(Self { executor: Some(executor), handle: None })
    }

    fn name(&self) -> String {
        "event-manager".to_string()
    }

    fn is_recoverable(&self) -> bool {
        true
    }

    fn join(&mut self) -> Vec<JoinHandle<Self::Error>> {
        vec![self.handle.take().unwrap()]
    }

    fn cleanup(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn start(&mut self) -> Result<(), Self::Error> {
        info!("Starting event manager executor...");

        let executor = self.executor.take().unwrap();
        let executor_handle = Builder::new()
            .name("event-manager-executor-main".to_string())
            .spawn(move || {
                let runtime = RuntimeBuilder::new_multi_thread()
                    .worker_threads(EVENT_MANAGER_N_THREADS)
                    .enable_all()
                    .build()
                    .unwrap();

                runtime.block_on(executor.execution_loop()).err().unwrap()
            })
            .map_err(err_str!(EventManagerError::SetupError))?;

        self.handle = Some(executor_handle);

        Ok(())
    }
}
