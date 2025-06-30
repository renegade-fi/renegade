//! Implements the `Worker` trait for the handshake manager

use std::thread::{Builder, JoinHandle};

use async_trait::async_trait;
use circuit_types::Amount;
use common::types::CancelChannel;
use common::worker::Worker;
use external_api::bus_message::SystemBusMessage;
use job_types::{
    handshake_manager::{HandshakeManagerQueue, HandshakeManagerReceiver},
    network_manager::NetworkManagerQueue,
    price_reporter::PriceReporterQueue,
    task_driver::TaskDriverQueue,
};
use state::State;
use system_bus::SystemBus;
use tokio::runtime::Builder as RuntimeBuilder;
use tracing::info;

use crate::manager::{
    HANDSHAKE_EXECUTOR_N_THREADS, HandshakeExecutor, init_price_streams,
    scheduler::HandshakeScheduler,
};

use super::{error::HandshakeManagerError, manager::HandshakeManager};

/// The max stack size for the handshake manager's threads
const HANDSHAKE_MANAGER_STACK_SIZE: usize = 1024 * 1024 * 10; // 10MB

/// The config type for the handshake manager
pub struct HandshakeManagerConfig {
    /// The minimum amount of the quote asset that the relayer should settle
    /// matches on
    pub min_fill_size: Amount,
    /// The relayer-global state
    pub state: State,
    /// The channel on which to send outbound network requests
    pub network_channel: NetworkManagerQueue,
    /// The price reporter's job queue
    pub price_reporter_job_queue: PriceReporterQueue,
    /// A sender on the handshake manager's job queue, used by the timer
    /// thread to enqueue outbound handshakes
    pub job_sender: HandshakeManagerQueue,
    /// The job queue on which to receive handshake requests
    pub job_receiver: Option<HandshakeManagerReceiver>,
    /// The queue used to send tasks to the driver
    pub task_queue: TaskDriverQueue,
    /// The system bus to which all workers have access
    pub system_bus: SystemBus<SystemBusMessage>,
    /// The channel on which the coordinator may mandate that the
    /// handshake manager cancel its execution
    pub cancel_channel: CancelChannel,
}

#[async_trait]
impl Worker for HandshakeManager {
    type WorkerConfig = HandshakeManagerConfig;
    type Error = HandshakeManagerError;

    async fn new(mut config: Self::WorkerConfig) -> Result<Self, Self::Error> {
        // Start a timer thread, periodically asks workers to begin handshakes with
        // peers
        let scheduler = HandshakeScheduler::new(
            config.job_sender.clone(),
            config.state.clone(),
            config.cancel_channel.clone(),
        );
        let executor = HandshakeExecutor::new(
            config.min_fill_size,
            config.job_receiver.take().unwrap(),
            config.network_channel.clone(),
            config.price_reporter_job_queue.clone(),
            config.state.clone(),
            config.task_queue.clone(),
            config.system_bus.clone(),
            config.cancel_channel.clone(),
        )?;

        Ok(HandshakeManager {
            config,
            executor: Some(executor),
            executor_handle: None,
            scheduler: Some(scheduler),
            scheduler_handle: None,
        })
    }

    fn is_recoverable(&self) -> bool {
        false
    }

    fn name(&self) -> String {
        "handshake-manager-main".to_string()
    }

    fn join(&mut self) -> Vec<JoinHandle<Self::Error>> {
        vec![self.executor_handle.take().unwrap(), self.scheduler_handle.take().unwrap()]
    }

    fn start(&mut self) -> Result<(), Self::Error> {
        info!("Starting executor loop for handshake protocol executor...");

        // Instruct the price reporter to being streaming prices for the default pairs
        init_price_streams(self.config.price_reporter_job_queue.clone())?;

        // Spawn both the executor and the scheduler in a thread
        let executor = self.executor.take().unwrap();
        let executor_handle = Builder::new()
            .name("handshake-executor-main".to_string())
            .spawn(move || {
                // Build a Tokio runtime for the handshake manager
                let runtime = RuntimeBuilder::new_multi_thread()
                    .enable_all()
                    .max_blocking_threads(HANDSHAKE_EXECUTOR_N_THREADS)
                    .thread_stack_size(HANDSHAKE_MANAGER_STACK_SIZE)
                    .build()
                    .unwrap();

                runtime.block_on(executor.execution_loop())
            })
            .map_err(|err| HandshakeManagerError::SetupError(err.to_string()))?;

        let scheduler = self.scheduler.take().unwrap();
        let scheduler_handle = Builder::new()
            .name("handshake-scheduler-main".to_string())
            .spawn(move || {
                let runtime = RuntimeBuilder::new_current_thread().enable_all().build().unwrap();
                runtime.block_on(scheduler.execution_loop())
            })
            .map_err(|err| HandshakeManagerError::SetupError(err.to_string()))?;

        self.executor_handle = Some(executor_handle);
        self.scheduler_handle = Some(scheduler_handle);

        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), Self::Error> {
        unimplemented!()
    }
}
