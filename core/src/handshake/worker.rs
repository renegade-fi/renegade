//! Implements the `Worker` trait for the handshake manager

use std::{
    sync::{Arc, RwLock},
    thread::JoinHandle,
};

use crossbeam::channel::{Receiver, Sender};
use rayon::ThreadPoolBuilder;
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    api::gossip::GossipOutbound,
    handshake::{
        handshake_cache::HandshakeCache,
        manager::{HandshakeJobRelay, HandshakeTimer, HANDSHAKE_CACHE_SIZE},
        state::HandshakeStateIndex,
    },
    state::RelayerState,
    types::SystemBusMessage,
    worker::Worker,
};

use super::{error::HandshakeManagerError, jobs::HandshakeExecutionJob, manager::HandshakeManager};

/// The number of threads executing handshakes
const NUM_HANDSHAKE_THREADS: usize = 8;

/// The config type for the handshake manager
#[derive(Debug)]
pub struct HandshakeManagerConfig {
    /// The relayer-global state
    pub global_state: RelayerState,
    /// The channel on which to send outbound network requests
    pub network_channel: UnboundedSender<GossipOutbound>,
    /// The job queue on which to receive handshake requrests
    pub job_receiver: Receiver<HandshakeExecutionJob>,
    /// The system bus to which all workers have access
    /// Sender
    #[allow(dead_code)]
    pub(crate) system_bus_sender: Sender<SystemBusMessage>,
    /// Receiver
    #[allow(dead_code)]
    pub(crate) system_bus_receiver: Receiver<SystemBusMessage>,
    /// The channel on which the coordinator may mandate that the
    /// handshake manager cancel its execution
    pub(crate) cancel_channel: Receiver<()>,
}

impl Worker for HandshakeManager {
    type WorkerConfig = HandshakeManagerConfig;
    type Error = HandshakeManagerError;

    fn new(config: Self::WorkerConfig) -> Result<Self, Self::Error> {
        // Build a thread pool to handle handshake operations
        println!("Starting execution loop for handshake protocol executor...");

        let thread_pool = Arc::new(
            ThreadPoolBuilder::new()
                .num_threads(NUM_HANDSHAKE_THREADS)
                .build()
                .unwrap(),
        );

        // The match results cache, used to avoid matching orders that have already
        // been determined not to intersect
        let handshake_cache = Arc::new(RwLock::new(HandshakeCache::new(HANDSHAKE_CACHE_SIZE)));

        // The handshake state cache; tracks in-flight handshakes state, fields, etc
        let handshake_state_index = HandshakeStateIndex::new();

        // Start a timer thread, periodically asks workers to begin handshakes with peers
        let timer = HandshakeTimer::new(
            thread_pool.clone(),
            handshake_state_index.clone(),
            handshake_cache.clone(),
            config.global_state.clone(),
            config.network_channel.clone(),
            config.cancel_channel.clone(),
        )?;
        let relay = HandshakeJobRelay::new(
            thread_pool,
            handshake_cache,
            handshake_state_index,
            config.job_receiver,
            config.network_channel,
            config.global_state,
            config.cancel_channel,
        )?;

        Ok(HandshakeManager { timer, relay })
    }

    fn is_recoverable(&self) -> bool {
        false
    }

    fn name(&self) -> String {
        "handshake-manager-main".to_string()
    }

    fn join(&mut self) -> Vec<JoinHandle<Self::Error>> {
        vec![self.relay.join_handle(), self.timer.join_handle()]
    }

    fn start(&mut self) -> Result<(), Self::Error> {
        // Does nothing, the `new` method handles setup for the handshake manager
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), Self::Error> {
        unimplemented!()
    }
}
