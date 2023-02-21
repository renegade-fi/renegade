//! Implements the `Worker` trait for the handshake manager

use std::thread::{Builder, JoinHandle};

use crossbeam::channel::{Receiver, Sender};
use tokio::sync::mpsc::UnboundedSender;
use tracing::log;

use crate::{
    api::gossip::GossipOutbound,
    handshake::manager::{HandshakeExecutor, HandshakeScheduler},
    proof_generation::jobs::ProofManagerJob,
    state::RelayerState,
    system_bus::SystemBus,
    types::SystemBusMessage,
    worker::Worker,
};

use super::{error::HandshakeManagerError, jobs::HandshakeExecutionJob, manager::HandshakeManager};

/// The config type for the handshake manager
#[derive(Debug)]
pub struct HandshakeManagerConfig {
    /// The relayer-global state
    pub global_state: RelayerState,
    /// The channel on which to send outbound network requests
    pub network_channel: UnboundedSender<GossipOutbound>,
    /// A sender on the handshake manager's job queue, used by the timer
    /// thread to enqueue outbound handshakes
    pub job_sender: Sender<HandshakeExecutionJob>,
    /// The job queue on which to receive handshake requests
    pub job_receiver: Receiver<HandshakeExecutionJob>,
    /// A sender to forward jobs to the proof manager on
    pub proof_manager_sender: Sender<ProofManagerJob>,
    /// The system bus to which all workers have access
    pub system_bus: SystemBus<SystemBusMessage>,
    /// The channel on which the coordinator may mandate that the
    /// handshake manager cancel its execution
    pub(crate) cancel_channel: Receiver<()>,
}

impl Worker for HandshakeManager {
    type WorkerConfig = HandshakeManagerConfig;
    type Error = HandshakeManagerError;

    fn new(config: Self::WorkerConfig) -> Result<Self, Self::Error> {
        // Start a timer thread, periodically asks workers to begin handshakes with peers
        let scheduler = HandshakeScheduler::new(
            config.job_sender.clone(),
            config.global_state.clone(),
            config.cancel_channel.clone(),
        );
        let executor = HandshakeExecutor::new(
            config.job_receiver.clone(),
            config.network_channel.clone(),
            config.proof_manager_sender.clone(),
            config.global_state.clone(),
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
        vec![
            self.executor_handle.take().unwrap(),
            self.scheduler_handle.take().unwrap(),
        ]
    }

    fn start(&mut self) -> Result<(), Self::Error> {
        log::info!("Starting executor loop for handshake protocol executor...");

        // Spawn both the executor and the scheduler in a thread
        let executor = self.executor.take().unwrap();
        let executor_handle = Builder::new()
            .name("handshake-executor-main".to_string())
            .spawn(move || executor.execution_loop())
            .map_err(|err| HandshakeManagerError::SetupError(err.to_string()))?;

        let scheduler = self.scheduler.take().unwrap();
        let scheduler_handle = Builder::new()
            .name("handshake-scheduler-main".to_string())
            .spawn(move || scheduler.execution_loop())
            .map_err(|err| HandshakeManagerError::SetupError(err.to_string()))?;

        self.executor_handle = Some(executor_handle);
        self.scheduler_handle = Some(scheduler_handle);

        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), Self::Error> {
        unimplemented!()
    }
}
