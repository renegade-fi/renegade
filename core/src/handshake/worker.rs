//! Implements the `Worker` trait for the handshake manager

use std::{sync::Arc, thread::JoinHandle};

use crossbeam::channel::Receiver;
use rayon::ThreadPoolBuilder;
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    api::gossip::GossipOutbound,
    handshake::manager::{HandshakeJobRelay, HandshakeTimer},
    state::GlobalRelayerState,
    worker::Worker,
};

use super::{error::HandshakeManagerError, jobs::HandshakeExecutionJob, manager::HandshakeManager};

// The number of threads executing handshakes
const NUM_HANDSHAKE_THREADS: usize = 8;

/// The config type for the handshake manager
#[derive(Debug)]
pub struct HandshakeManagerConfig {
    /// The relayer-global state
    pub global_state: GlobalRelayerState,
    /// The channel on which to send outbound network requests
    pub network_channel: UnboundedSender<GossipOutbound>,
    /// The job queue on which to receive handshake requrests
    pub job_receiver: Receiver<HandshakeExecutionJob>,
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

        // Start a timer thread
        let timer = HandshakeTimer::new(
            thread_pool.clone(),
            config.global_state,
            config.network_channel.clone(),
        )?;
        let relay =
            HandshakeJobRelay::new(thread_pool, config.job_receiver, config.network_channel)?;

        Ok(HandshakeManager { timer, relay })
    }

    fn is_recoverable(&self) -> bool {
        true
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
