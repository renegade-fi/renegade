//! Implements the `Worker` trait for the GossipServer

use futures::executor::block_on;
use libp2p::Multiaddr;
use std::thread::{Builder, JoinHandle};
use tokio::runtime::Builder as RuntimeBuilder;
use tokio::sync::mpsc::{Receiver, Sender, UnboundedSender as TokioSender};

use crate::{api::gossip::GossipOutbound, state::RelayerState, worker::Worker, CancelChannel};

use super::server::{GOSSIP_EXECUTOR_N_BLOCKING_THREADS, GOSSIP_EXECUTOR_N_THREADS};
use super::{
    errors::GossipError,
    jobs::GossipServerJob,
    server::{GossipProtocolExecutor, GossipServer},
    types::{ClusterId, WrappedPeerId},
};

/// The configuration passed from the coordinator to the GossipServer
#[derive(Debug)]
pub struct GossipServerConfig {
    /// The libp2p PeerId of the local peer
    pub(crate) local_peer_id: WrappedPeerId,
    /// The multiaddr of the local peer
    pub(crate) local_addr: Multiaddr,
    /// The cluster ID of the local peer
    pub(crate) cluster_id: ClusterId,
    /// The servers to bootstrap into the network with
    pub(crate) bootstrap_servers: Vec<(WrappedPeerId, Multiaddr)>,
    /// A reference to the relayer-global state
    pub(crate) global_state: RelayerState,
    /// A job queue to send outbound heartbeat requests on
    pub(crate) job_sender: Sender<GossipServerJob>,
    /// A job queue to receive inbound heartbeat requests on
    pub(crate) job_receiver: Option<Receiver<GossipServerJob>>,
    /// A job queue to send outbound network requests on
    pub(crate) network_sender: TokioSender<GossipOutbound>,
    /// The channel on which the coordinator may mandate that the
    /// gossip server cancel its execution
    pub(crate) cancel_channel: CancelChannel,
}

impl Worker for GossipServer {
    type WorkerConfig = GossipServerConfig;
    type Error = GossipError;

    fn new(config: Self::WorkerConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            config,
            protocol_executor_handle: None,
        })
    }

    fn is_recoverable(&self) -> bool {
        true
    }

    fn name(&self) -> String {
        "gossip-server-main".to_string()
    }

    fn join(&mut self) -> Vec<JoinHandle<Self::Error>> {
        vec![self.protocol_executor_handle.take().unwrap()]
    }

    fn start(&mut self) -> Result<(), Self::Error> {
        // Start the heartbeat executor, this worker manages pinging peers and responding to
        // heartbeat requests from peers
        let protocol_executor = GossipProtocolExecutor::new(
            self.config.local_peer_id,
            self.config.network_sender.clone(),
            self.config.job_receiver.take().unwrap(),
            self.config.global_state.clone(),
            self.config.cancel_channel.clone(),
        )?;

        let sender = self.config.job_sender.clone();
        let executor_handle = Builder::new()
            .name("gossip-executor-main".to_string())
            .spawn(move || {
                // Build a runtime for the gossip server to work in, then enter the runtime via
                // the gossip server's execution loop
                let tokio_runtime = RuntimeBuilder::new_multi_thread()
                    .worker_threads(GOSSIP_EXECUTOR_N_THREADS)
                    .max_blocking_threads(GOSSIP_EXECUTOR_N_BLOCKING_THREADS)
                    .enable_all()
                    .build()
                    .unwrap();

                tokio_runtime
                    .block_on(protocol_executor.execution_loop(sender))
                    .err()
                    .unwrap()
            })
            .map_err(|err| GossipError::ServerSetup(err.to_string()))?;
        self.protocol_executor_handle = Some(executor_handle);

        // Bootstrap the local peer into the gossip network
        block_on(async { self.bootstrap_into_network().await })?;

        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), Self::Error> {
        unimplemented!()
    }
}
