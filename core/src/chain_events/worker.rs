//! The relayer worker implementation for the event listener

use std::thread::{self, Builder, JoinHandle};
use tokio::runtime::Builder as RuntimeBuilder;
use tracing::log;

use crate::worker::Worker;

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
        let executor = if config.enabled() {
            Some(OnChainEventListenerExecutor::new(config.clone()))
        } else {
            None
        };

        Ok(Self {
            config,
            executor,
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
        let executor = self.executor.take();
        let join_handle = Builder::new()
            .name("on-chain-event-listener-executor".to_string())
            .spawn(move || {
                // If we were unable to build an executor from the config, park the executing thread
                // This is simpler than forcing some partial-operating logic up to the coordinator
                if let Some(executor) = executor {
                    let runtime = RuntimeBuilder::new_current_thread()
                        .enable_all()
                        .thread_name("on-chain-listener-runtime")
                        .build()
                        .map_err(|err| OnChainEventListenerError::Setup(err.to_string()));
                    if let Err(e) = runtime {
                        return e;
                    }

                    let runtime = runtime.unwrap();
                    runtime.block_on(executor.execute())
                } else {
                    log::info!("on-chain event listener missing config options; parking worker...");
                    thread::park();
                    unreachable!();
                }
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
