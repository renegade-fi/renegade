//! Defines the implementation of the `Worker` trait for the network manager

use std::thread::{Builder, JoinHandle};

use crossbeam::channel::Sender;
use futures::executor::block_on;
use libp2p::{identity, Multiaddr, Swarm};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::{
    api::gossip::GossipOutbound,
    gossip::{
        jobs::HeartbeatExecutorJob,
        types::{PeerInfo, WrappedPeerId},
    },
    handshake::jobs::HandshakeExecutionJob,
    network_manager::composed_protocol::ComposedNetworkBehavior,
    state::GlobalRelayerState,
    worker::Worker,
};

use super::{error::NetworkManagerError, manager::NetworkManager};

/// The worker configuration for the newtork manager
#[derive(Debug)]
pub struct NetworkManagerConfig {
    /// The port to listen for inbound traffic on
    pub(crate) port: u32,
    /// The channel on which to receive requests from other workers
    /// for outbound traffic
    /// This is wrapped in an option to allow the worker thread to take
    /// ownership of the work queue once it is started. The coordinator
    /// will be left with `None` after this happens
    pub(crate) send_channel: Option<UnboundedReceiver<GossipOutbound>>,
    /// The work queue to forward inbound hearbeat requests to
    pub(crate) heartbeat_work_queue: Sender<HeartbeatExecutorJob>,
    /// The work queue to forward inbound handshake requests to
    pub(crate) handshake_work_queue: Sender<HandshakeExecutionJob>,
    /// The global shared state of the local relayer
    pub(crate) global_state: GlobalRelayerState,
}

impl Worker for NetworkManager {
    type WorkerConfig = NetworkManagerConfig;
    type Error = NetworkManagerError;

    fn new(config: Self::WorkerConfig) -> Result<Self, Self::Error> {
        // Generate an keypair on curve 25519 for the local peer
        let local_keypair = identity::Keypair::generate_ed25519();
        let local_peer_id = WrappedPeerId(local_keypair.public().to_peer_id());
        println!("peer ID: {:?}", local_peer_id);

        // Update global state with newly assigned peerID
        {
            let mut locked_state = config
                .global_state
                .write()
                .expect("global state lock poisoned");
            locked_state.local_peer_id = Some(local_peer_id);
        } // locked_state released here

        Ok(Self {
            config,
            local_peer_id,
            local_keypair,
            thread_handle: None,
        })
    }

    fn is_recoverable(&self) -> bool {
        true
    }

    fn join(&mut self) -> JoinHandle<Self::Error> {
        // Allow panic if server is not started yet
        self.thread_handle.take().unwrap()
    }

    fn start(&mut self) -> Result<(), Self::Error> {
        // Build a transport and connect it to the P2P swarm
        // TODO: Migrate this to QUIC
        let transport = block_on(libp2p::development_transport(self.local_keypair.clone()))
            .map_err(|err| NetworkManagerError::SetupError(err.to_string()))?;

        // Behavior is a composed behavior of RequestResponse with Kademlia
        let mut behavior = ComposedNetworkBehavior::new(*self.local_peer_id);

        // Add any bootstrap addresses to the peer info table
        for (peer_id, peer_info) in self.config.global_state.read().unwrap().known_peers.iter() {
            println!(
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
        let mut swarm = Swarm::new(transport, behavior, *self.local_peer_id);
        let hostport = format!("/ip4/127.0.0.1/tcp/{}", self.config.port);
        let addr: Multiaddr = hostport.parse().unwrap();
        swarm
            .listen_on(addr.clone())
            .map_err(|err| NetworkManagerError::SetupError(err.to_string()))?;

        // Add self to known peers
        self.config
            .global_state
            .write()
            .unwrap()
            .known_peers
            .insert(self.local_peer_id, PeerInfo::new(self.local_peer_id, addr));

        // Start up the worker thread
        let peer_id_copy = self.local_peer_id;
        let heartbeat_work_queue = self.config.heartbeat_work_queue.clone();
        let handshake_work_queue = self.config.handshake_work_queue.clone();
        // Take ownership of the work queue
        let send_channel = self.config.send_channel.take().unwrap();

        let thread_handle = Builder::new()
            .name("network-manager".to_string())
            .spawn(move || {
                // Block on this to execute the future in a separate thread
                block_on(Self::executor_loop(
                    peer_id_copy,
                    swarm,
                    send_channel,
                    heartbeat_work_queue,
                    handshake_work_queue,
                ))
                .err()
                .unwrap()
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
