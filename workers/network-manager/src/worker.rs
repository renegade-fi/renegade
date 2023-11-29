//! Defines the implementation of the `Worker` trait for the network manager

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::thread::{Builder, JoinHandle};

use common::types::gossip::ClusterId;
use common::types::CancelChannel;
use common::worker::Worker;
use ed25519_dalek::Keypair;
use external_api::bus_message::SystemBusMessage;
use futures::executor::block_on;
use gossip_api::gossip::GossipOutbound;
use job_types::{gossip_server::GossipServerJob, handshake_manager::HandshakeExecutionJob};
use state::RelayerState;
use system_bus::SystemBus;

use libp2p::multiaddr::{Multiaddr, Protocol};
use libp2p::quic::{tokio::Transport as QuicTransport, Config as QuicConfig};
use libp2p_core::muxing::StreamMuxerBox;
use libp2p_core::Transport;
use libp2p_swarm::SwarmBuilder;
use tokio::runtime::Builder as TokioRuntimeBuilder;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing::log;

use crate::composed_protocol::ComposedNetworkBehavior;

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
    pub port: u16,
    /// The address to bind to for inbound traffic
    pub bind_addr: IpAddr,
    /// The cluster ID of the local peer
    pub cluster_id: ClusterId,
    /// Whether or not to allow discovery of peers on the localhost
    pub allow_local: bool,
    /// The cluster keypair, wrapped in an option to allow the worker thread to
    /// take ownership of the keypair
    pub cluster_keypair: Option<Keypair>,
    /// The known public addr that the local node is listening behind, if one
    /// exists
    pub known_public_addr: Option<SocketAddr>,
    /// The channel on which to receive requests from other workers
    /// for outbound traffic
    /// This is wrapped in an option to allow the worker thread to take
    /// ownership of the work queue once it is started. The coordinator
    /// will be left with `None` after this happens
    pub send_channel: Option<UnboundedReceiver<GossipOutbound>>,
    /// The work queue to forward inbound heartbeat requests to
    pub gossip_work_queue: UnboundedSender<GossipServerJob>,
    /// The work queue to forward inbound handshake requests to
    pub handshake_work_queue: UnboundedSender<HandshakeExecutionJob>,
    /// The system bus, used to stream internal pubsub messages
    pub system_bus: SystemBus<SystemBusMessage>,
    /// The global shared state of the local relayer
    pub global_state: RelayerState,
    /// The channel on which the coordinator can send a cancel signal to
    /// all network worker threads
    pub cancel_channel: CancelChannel,
}

impl Worker for NetworkManager {
    type WorkerConfig = NetworkManagerConfig;
    type Error = NetworkManagerError;

    fn new(config: Self::WorkerConfig) -> Result<Self, Self::Error> {
        let local_peer_id = config.global_state.local_peer_id;
        let local_keypair = config.global_state.local_keypair.clone();

        // If the local node is given a known dialable addr for itself at startup,
        // construct the local addr directly, otherwise set it to the canonical
        // unspecified addr targeting all network interfaces and allow it to be
        // discovered via the `Identify` protocol
        let ip_protoc = config
            .known_public_addr
            .map(|socketaddr| match socketaddr.ip() {
                IpAddr::V4(addr) => Protocol::Ip4(addr),
                IpAddr::V6(addr) => Protocol::Ip6(addr),
            })
            .unwrap_or_else(|| Protocol::Ip4(Ipv4Addr::new(0, 0, 0, 0)));

        let local_addr = Multiaddr::empty()
            .with(Protocol::P2p(local_peer_id.0.into()))
            .with(Protocol::Tcp(config.port))
            .with(ip_protoc);

        Ok(Self {
            cluster_id: config.cluster_id.clone(),
            config,
            local_peer_id,
            local_keypair,
            local_addr,
            thread_handle: None,
        })
    }

    /// The network manager is not recoverable because restarting it requires
    /// re-allocating its work queue. This would require updating any
    /// senders on this queue as well, it is simpler to just fail
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
        // Build a quic transport
        let hostport = format!("/ip4/{}/udp/{}/quic-v1", self.config.bind_addr, self.config.port);
        let addr: Multiaddr = hostport.parse().unwrap();

        // Build the quic transport
        let config = QuicConfig::new(&self.local_keypair);
        let quic_transport = QuicTransport::new(config)
            .map(|(peer_id, quic_conn), _| (peer_id, StreamMuxerBox::new(quic_conn)))
            .boxed();

        // Defines the behaviors of the underlying networking stack: including gossip,
        // pubsub, address discovery, etc
        let mut behavior = ComposedNetworkBehavior::new(
            *self.local_peer_id,
            ProtocolVersion::Version0,
            &self.local_keypair,
        )?;

        // Add any bootstrap addresses to the peer info table
        let peer_index = block_on(async {
            self.config.global_state.read_peer_index().await.get_info_map().await
        });

        for (peer_id, peer_info) in peer_index.iter() {
            log::info!("Adding {:?}: {} to routing table...", peer_id, peer_info.get_addr());
            behavior.kademlia_dht.add_address(peer_id, peer_info.get_addr());
        }

        // Connect the behavior and the transport via swarm and enter the network
        let mut swarm =
            SwarmBuilder::with_tokio_executor(quic_transport, behavior, *self.local_peer_id)
                .build();
        swarm.listen_on(addr).map_err(|err| NetworkManagerError::SetupError(err.to_string()))?;

        // After assigning address and peer ID, update the global state
        block_on(self.update_global_state_after_startup());
        // Subscribe to all relevant topics
        self.setup_pubsub_subscriptions(&mut swarm)?;

        // Start up the worker thread
        let executor = NetworkManagerExecutor::new(
            self.config.port,
            self.local_peer_id,
            self.config.allow_local,
            self.config.cluster_keypair.take().unwrap(),
            swarm,
            self.config.send_channel.take().unwrap(),
            self.config.gossip_work_queue.clone(),
            self.config.handshake_work_queue.clone(),
            self.config.global_state.clone(),
            self.config.system_bus.clone(),
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
        Ok(())
    }
}
