//! Implements the `Worker` trait for the handshake manager

use std::thread::{Builder, JoinHandle};

use async_trait::async_trait;
use circuit_types::Amount;
use job_types::{
    matching_engine::{MatchingEngineWorkerQueue, MatchingEngineWorkerReceiver},
    network_manager::NetworkManagerQueue,
    task_driver::TaskDriverQueue,
};
use matching_engine_core::MatchingEngine;
use price_state::PriceStreamStates;
use state::State;
use system_bus::SystemBus;
use tokio::runtime::Builder as RuntimeBuilder;
use tracing::info;
use types_runtime::{CancelChannel, Worker};

use crate::{
    error::MatchingEngineError,
    executor::{MATCHING_ENGINE_EXECUTOR_N_THREADS, MatchingEngineExecutor},
};

/// The max stack size for the matching engine's threads
const MATCHING_ENGINE_STACK_SIZE: usize = 1024 * 1024 * 10; // 10MB

/// The config type for the matching engine
pub struct MatchingEngineConfig {
    /// The minimum amount of the quote asset that the relayer should settle
    /// matches on
    pub min_fill_size: Amount,
    /// The relayer-global state
    pub state: State,
    /// The matching engine instance
    pub matching_engine: MatchingEngine,
    /// The price streams from the price reporter
    pub price_streams: PriceStreamStates,
    /// The job queue on which to receive matching engine requests
    pub job_receiver: Option<MatchingEngineWorkerReceiver>,
    /// The queue used to send tasks to the driver
    pub task_queue: TaskDriverQueue,
    /// The system bus to which all workers have access
    pub system_bus: SystemBus,
    /// The channel on which the coordinator may mandate that the
    /// matching engine cancel its execution
    pub cancel_channel: CancelChannel,
}

/// Manages requests to match orders
pub struct MatchingEngineManager {
    /// The config on the matching engine
    pub config: MatchingEngineConfig,
    /// The executor, ownership is taken by the controlling thread when started
    pub executor: Option<MatchingEngineExecutor>,
    /// The join handle for the executor thread
    pub executor_handle: Option<JoinHandle<MatchingEngineError>>,
}

#[async_trait]
impl Worker for MatchingEngineManager {
    type WorkerConfig = MatchingEngineConfig;
    type Error = MatchingEngineError;

    async fn new(mut config: Self::WorkerConfig) -> Result<Self, Self::Error> {
        // Start a timer thread, periodically asks workers to begin handshakes with
        // peers
        let executor = MatchingEngineExecutor::new(
            config.min_fill_size,
            config.job_receiver.take().unwrap(),
            config.price_streams.clone(),
            config.state.clone(),
            config.matching_engine.clone(),
            config.task_queue.clone(),
            config.system_bus.clone(),
            config.cancel_channel.clone(),
        )?;

        Ok(MatchingEngineManager { config, executor: Some(executor), executor_handle: None })
    }

    fn is_recoverable(&self) -> bool {
        false
    }

    fn name(&self) -> String {
        "handshake-manager-main".to_string()
    }

    fn join(&mut self) -> Vec<JoinHandle<Self::Error>> {
        vec![self.executor_handle.take().unwrap()]
    }

    fn start(&mut self) -> Result<(), Self::Error> {
        info!("Starting executor loop for handshake protocol executor...");

        // Spawn both the executor and the scheduler in a thread
        let executor = self.executor.take().unwrap();
        let executor_handle = Builder::new()
            .name("handshake-executor-main".to_string())
            .spawn(move || {
                // Build a Tokio runtime for the handshake manager
                let runtime = RuntimeBuilder::new_multi_thread()
                    .enable_all()
                    .max_blocking_threads(MATCHING_ENGINE_EXECUTOR_N_THREADS)
                    .thread_stack_size(MATCHING_ENGINE_STACK_SIZE)
                    .build()
                    .unwrap();

                runtime.block_on(executor.execution_loop())
            })
            .map_err(MatchingEngineError::setup)?;

        self.executor_handle = Some(executor_handle);
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), Self::Error> {
        unimplemented!()
    }
}
