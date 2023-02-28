//! The relayer worker implementation for the event listener

use crate::worker::Worker;

use super::{
    error::OnChainEventListenerError,
    listener::{OnChainEventListener, OnChainEventListenerConfig},
};

impl Worker for OnChainEventListener {
    type WorkerConfig = OnChainEventListenerConfig;
    type Error = OnChainEventListenerError;

    fn new(config: Self::WorkerConfig) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(Self { config })
    }

    fn name(&self) -> String {
        "on-chain-event-listener".to_string()
    }

    fn join(&mut self) -> Vec<std::thread::JoinHandle<Self::Error>> {
        unimplemented!()
    }

    fn start(&mut self) -> Result<(), Self::Error> {
        unimplemented!("")
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
