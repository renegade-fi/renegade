//! Defines the implementation of the `Worker` trait for the network manager

use std::thread::{Builder, JoinHandle};

use ed25519_dalek::Keypair;
use futures::executor::block_on;
use libp2p::Multiaddr;
use libp2p_swarm::SwarmBuilder;
use tokio::runtime::Builder as TokioRuntimeBuilder;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing::log;

use crate::{
    gossip::{jobs::GossipServerJob, types::ClusterId},
    gossip_api::gossip::GossipOutbound,
    handshake::jobs::HandshakeExecutionJob,
    network_manager::composed_protocol::ComposedNetworkBehavior,
    state::RelayerState,
    worker::Worker,
    CancelChannel,
};

use super::{
    composed_protocol::ProtocolVersion,
    error::NetworkManagerError,
    manager::{NetworkManager, NetworkManagerExecutor},
};

/// The number of threads backing the network
const NETWORK_MANAGER_N_THREADS: usize = 3;

/// The worker configuration for the network manager
#[derive(Debug)]
pub struct NetworkManagerConfig {
    /// The port to listen for inbound traffic on
    pub(crate) port: u16,
    /// The cluster ID of the local peer
    pub(crate) cluster_id: ClusterId,
    /// The cluster keypair, wrapped in an option to allow the worker thread to
    /// take ownership of the keypair
    pub(crate) cluster_keypair: Option<Keypair>,
    /// The channel on which to receive requests from other workers
    /// for outbound traffic
    /// This is wrapped in an option to allow the worker thread to take
    /// ownership of the work queue once it is started. The coordinator
    /// will be left with `None` after this happens
    pub(crate) send_channel: Option<UnboundedReceiver<GossipOutbound>>,
    /// The work queue to forward inbound heartbeat requests to
    pub(crate) gossip_work_queue: UnboundedSender<GossipServerJob>,
    /// The work queue to forward inbound handshake requests to
    pub(crate) handshake_work_queue: UnboundedSender<HandshakeExecutionJob>,
    /// The global shared state of the local relayer
    pub(crate) global_state: RelayerState,
    /// The channel on which the coordinator can send a cancel signal to
    /// all network worker threads
    pub(crate) cancel_channel: CancelChannel,
}

impl Worker for NetworkManager {
    type WorkerConfig = NetworkManagerConfig;
    type Error = NetworkManagerError;

    fn new(config: Self::WorkerConfig) -> Result<Self, Self::Error> {
        let local_peer_id = config.global_state.local_peer_id;
        let local_keypair = config.global_state.local_keypair.clone();
        Ok(Self {
            cluster_id: config.cluster_id.clone(),
            config,
            local_peer_id,
            local_keypair,
            local_addr: Multiaddr::empty(),
            thread_handle: None,
        })
    }

    /// The network manager is not recoverable because restarting it requires re-allocating its
    /// work queue. This would require updating any senders on this queue as well, it is simpler
    /// to just fail
    fn is_recoverable(&self) -> bool {
        false
    }

    fn name(&self) -> String {
        "network-manager-main".to_string()
    }

    fn join(&mut self) -> Vec<JoinHandle<Self::Error>> {
        // Allow panic if server is not started yet
        vec![self.thread_handle.take().unwrap()]
    }

    fn start(&mut self) -> Result<(), Self::Error> {
        // Build a transport and connect it to the P2P swarm
        // TODO: Migrate this to QUIC
        let transport = block_on(libp2p::development_transport(self.local_keypair.clone()))
            .map_err(|err| NetworkManagerError::SetupError(err.to_string()))?;

        // Behavior is a composed behavior of RequestResponse with Kademlia
        let mut behavior = ComposedNetworkBehavior::new(
            *self.local_peer_id,
            ProtocolVersion::Version0,
            self.local_keypair.clone(),
        )?;

        // Add any bootstrap addresses to the peer info table
        let peer_index = block_on(async {
            self.config
                .global_state
                .read_peer_index()
                .await
                .get_info_map()
                .await
        });
        for (peer_id, peer_info) in peer_index.iter() {
            log::info!(
                "Adding {:?}: {} to routing table...",
                peer_id,
                peer_info.get_addr()
            );
            behavior
                .kademlia_dht
                .add_address(peer_id, peer_info.get_addr());
        }

        // Connect the behavior and the transport via swarm
        // and begin listening for requests
        let mut swarm =
            SwarmBuilder::with_tokio_executor(transport, behavior, *self.local_peer_id).build();
        let hostport = format!("/ip4/0.0.0.0/tcp/{}", self.config.port);
        let addr: Multiaddr = hostport.parse().unwrap();
        self.local_addr = addr.clone();

        swarm
            .listen_on(addr)
            .map_err(|err| NetworkManagerError::SetupError(err.to_string()))?;

        // After assigning address and peer ID, update the global state
        block_on(self.update_global_state_after_startup());

        // Subscribe to all relevant topics
        self.setup_pubsub_subscriptions(&mut swarm)?;

        // Start up the worker thread
        let executor = NetworkManagerExecutor::new(
            self.config.port,
            self.local_peer_id,
            self.config.cluster_keypair.take().unwrap(),
            swarm,
            self.config.send_channel.take().unwrap(),
            self.config.gossip_work_queue.clone(),
            self.config.handshake_work_queue.clone(),
            self.config.global_state.clone(),
            self.config.cancel_channel.clone(),
        );

        let thread_handle = Builder::new()
            .name("network-manager-main-loop".to_string())
            .spawn(move || {
                // Build a tokio runtime for the network manager
                let runtime = TokioRuntimeBuilder::new_multi_thread()
                    .worker_threads(NETWORK_MANAGER_N_THREADS)
                    .enable_all()
                    .build()
                    .expect("building a runtime to the network manager failed");

                // Block on this to execute the future in a separate thread
                runtime.block_on(executor.executor_loop())
            })
            .map_err(|err| NetworkManagerError::SetupError(err.to_string()))?;

        self.thread_handle = Some(thread_handle);
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), Self::Error> {
        if self.config.send_channel.is_some() {
            self.config.send_channel.take().unwrap().close();
        }

        Ok(())
    }
}
