//! The relayer worker implementation for the event listener

use std::thread::{Builder, JoinHandle};

use async_trait::async_trait;
use darkpool_client::DarkpoolClient;
use job_types::{event_manager::EventManagerQueue, matching_engine::MatchingEngineWorkerQueue};
use state::State;
use system_bus::SystemBus;
use tokio::runtime::Builder as RuntimeBuilder;
use tracing::error;
use types_runtime::{CancelChannel, Worker};

use crate::{error::OnChainEventListenerError, executor::OnChainEventListenerExecutor};

/// The configuration passed to the listener upon startup
#[derive(Clone)]
pub struct OnChainEventListenerConfig {
    /// The ethereum websocket address to use for streaming events
    pub websocket_addr: Option<String>,
    /// A darkpool client for listening to events
    pub darkpool_client: DarkpoolClient,
    /// A copy of the relayer global state
    pub global_state: State,
    /// The channel on which the coordinator may send a cancel signal
    pub cancel_channel: CancelChannel,
    /// A sender to the event manager's queue
    pub event_queue: EventManagerQueue,
    /// A sender to the matching engine worker's queue
    pub matching_engine_queue: MatchingEngineWorkerQueue,
    /// The system bus for internal pub/sub notifications
    pub system_bus: SystemBus,
}

/// The worker responsible for listening for on-chain events, translating them
/// to jobs for other workers, and forwarding these jobs to the relevant workers
pub struct OnChainEventListener {
    /// The executor run in a separate thread
    pub(crate) executor: Option<OnChainEventListenerExecutor>,
    /// The thread handle of the executor
    pub(crate) executor_handle: Option<JoinHandle<OnChainEventListenerError>>,
}

#[async_trait]
impl Worker for OnChainEventListener {
    type WorkerConfig = OnChainEventListenerConfig;
    type Error = OnChainEventListenerError;

    async fn new(config: Self::WorkerConfig) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let executor = OnChainEventListenerExecutor::new(config);
        Ok(Self { executor: Some(executor), executor_handle: None })
    }

    fn name(&self) -> String {
        "on-chain-event-listener".to_string()
    }

    fn join(&mut self) -> Vec<JoinHandle<Self::Error>> {
        vec![self.executor_handle.take().unwrap()]
    }

    fn start(&mut self) -> Result<(), Self::Error> {
        let executor = self.executor.take().unwrap();
        let join_handle = Builder::new()
            .name("on-chain-event-listener-executor".to_string())
            .spawn(move || {
                let runtime = match RuntimeBuilder::new_current_thread()
                    .enable_all()
                    .thread_name("on-chain-listener-runtime")
                    .build()
                {
                    Ok(rt) => rt,
                    Err(err) => return OnChainEventListenerError::Setup(err.to_string()),
                };

                runtime.block_on(async {
                    if let Err(e) = executor.execute().await {
                        error!("Chain event listener crashed with error: {e}");
                        return e;
                    }
                    OnChainEventListenerError::StreamEnded
                })
            })
            .map_err(|err| OnChainEventListenerError::Setup(err.to_string()))?;

        self.executor_handle = Some(join_handle);
        Ok(())
    }

    fn is_recoverable(&self) -> bool {
        false
    }

    fn recover(self) -> Self
    where
        Self: Sized,
    {
        unimplemented!("")
    }

    fn cleanup(&mut self) -> Result<(), Self::Error> {
        unimplemented!("")
    }
}
