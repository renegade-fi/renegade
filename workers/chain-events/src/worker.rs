//! The relayer worker implementation for the event listener

use common::worker::Worker;
use std::thread::{Builder, JoinHandle};
use tokio::runtime::Builder as RuntimeBuilder;
use tracing::error;

use super::{
    error::OnChainEventListenerError,
    listener::{OnChainEventListener, OnChainEventListenerConfig, OnChainEventListenerExecutor},
};

impl Worker for OnChainEventListener {
    type WorkerConfig = OnChainEventListenerConfig;
    type Error = OnChainEventListenerError;

    fn new(config: Self::WorkerConfig) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let executor = OnChainEventListenerExecutor::new(config);

        Ok(Self {
            executor: Some(executor),
            // Replaced at startup
            executor_handle: None,
        })
    }

    fn name(&self) -> String {
        "on-chain-event-listener".to_string()
    }

    fn join(&mut self) -> Vec<JoinHandle<Self::Error>> {
        vec![self.executor_handle.take().unwrap()]
    }

    fn start(&mut self) -> Result<(), Self::Error> {
        // Spawn the execution loop in a separate thread
        let executor = self.executor.take().unwrap();
        let join_handle = Builder::new()
            .name("on-chain-event-listener-executor".to_string())
            .spawn(move || {
                let runtime = RuntimeBuilder::new_current_thread()
                    .enable_all()
                    .thread_name("on-chain-listener-runtime")
                    .build()
                    .map_err(|err| OnChainEventListenerError::Setup(err.to_string()));
                if let Err(e) = runtime {
                    return e;
                }

                let runtime = runtime.unwrap();
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
