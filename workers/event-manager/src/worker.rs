//! Defines the worker implementation for the event manager

use std::thread::JoinHandle;

use async_trait::async_trait;
use common::{types::CancelChannel, worker::Worker};
use job_types::event_manager::EventManagerReceiver;
use libp2p::Multiaddr;

use crate::error::EventManagerError;

// ----------
// | Config |
// ----------

/// The configuration for the event manager
pub struct EventManagerConfig {
    /// The address to export relayer events to
    pub event_export_addr: Option<Multiaddr>,
    /// The queue on which to receive events
    pub event_queue: EventManagerReceiver,
    /// The channel on which the coordinator may mandate that the
    /// event manager cancel its execution
    pub cancel_channel: CancelChannel,
}

// ----------
// | Worker |
// ----------

/// The event manager worker
pub struct EventManager {
    /// The configuration for the event manager
    pub config: EventManagerConfig,
    /// The handle on the event manager
    pub handle: Option<JoinHandle<EventManagerError>>,
}

#[async_trait]
impl Worker for EventManager {
    type WorkerConfig = EventManagerConfig;
    type Error = EventManagerError;

    async fn new(config: Self::WorkerConfig) -> Result<Self, Self::Error> {
        Ok(Self { config, handle: None })
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
        todo!()
    }
}
