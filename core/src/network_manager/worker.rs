//! Defines the implementation of the `Worker` trait for the network manager

use std::thread::{Builder, JoinHandle};

use crossbeam::channel::{Receiver, Sender};
use ed25519_dalek::Keypair;
use futures::executor::block_on;
use libp2p::{identity, Multiaddr, Swarm};
use tokio::sync::mpsc::{self, UnboundedReceiver};

use crate::{
    api::gossip::GossipOutbound,
    gossip::{
        jobs::GossipServerJob,
        types::{ClusterId, WrappedPeerId},
    },
    handshake::jobs::HandshakeExecutionJob,
    network_manager::composed_protocol::ComposedNetworkBehavior,
    state::RelayerState,
    types::SystemBusMessage,
    worker::Worker,
};

use super::{error::NetworkManagerError, manager::NetworkManager};

/// The worker configuration for the newtork manager
#[derive(Debug)]
pub struct NetworkManagerConfig {
    /// The port to listen for inbound traffic on
    pub(crate) port: u32,
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
    /// The work queue to forward inbound hearbeat requests to
    pub(crate) heartbeat_work_queue: Sender<GossipServerJob>,
    /// The work queue to forward inbound handshake requests to
    pub(crate) handshake_work_queue: Sender<HandshakeExecutionJob>,
    /// The system bus to which all workers have access
    /// Sender
    #[allow(dead_code)]
    pub(crate) system_bus_sender: Sender<SystemBusMessage>,
    /// Receiver
    #[allow(dead_code)]
    pub(crate) system_bus_receiver: Receiver<SystemBusMessage>,
    /// The global shared state of the local relayer
    pub(crate) global_state: RelayerState,
    /// The channel on which the coordinator can send a cancel signal to
    /// all network worker threads
    pub(crate) cancel_channel: Receiver<()>,
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
            let mut locked_peer_id = config.global_state.write_peer_id();
            *locked_peer_id = local_peer_id;
        } // locked_state released here

        Ok(Self {
            cluster_id: config.cluster_id.clone(),
            config,
            local_peer_id,
            local_addr: Multiaddr::empty(),
            local_keypair,
            thread_handle: None,
            cancellation_relay_handle: None,
        })
    }

    /// The network manager is not recoverable because restarting it requires re-allocating its
    /// work queue. This would require updating any senders on this queue as well, it is simpler
    /// to just fail
    fn is_recoverable(&self) -> bool {
        false
    }

    fn join(&mut self) -> Vec<JoinHandle<Self::Error>> {
        // Allow panic if server is not started yet
        vec![
            self.thread_handle.take().unwrap(),
            self.cancellation_relay_handle.take().unwrap(),
        ]
    }

    fn start(&mut self) -> Result<(), Self::Error> {
        // Build a transport and connect it to the P2P swarm
        // TODO: Migrate this to QUIC
        let transport = block_on(libp2p::development_transport(self.local_keypair.clone()))
            .map_err(|err| NetworkManagerError::SetupError(err.to_string()))?;

        // Behavior is a composed behavior of RequestResponse with Kademlia
        let mut behavior =
            ComposedNetworkBehavior::new(*self.local_peer_id, self.local_keypair.clone())?;

        // Add any bootstrap addresses to the peer info table
        for (peer_id, peer_info) in self.config.global_state.read_known_peers().iter() {
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
        self.local_addr = addr.clone();
        swarm
            .listen_on(addr)
            .map_err(|err| NetworkManagerError::SetupError(err.to_string()))?;

        // After assigning address and peer ID, update the global state
        self.update_global_state_after_startup();

        // Subscribe to all relevant topics
        self.setup_pubsub_subscriptions(&mut swarm)?;

        // Start up a cancel forwarder, this thread forwards from a crossbeam cancel
        // channel to an async queue to shim between blocking and async interfaces
        // TODO: Maybe use crossfire for this instead
        let (async_cancel_sender, async_cancel_receiver) = mpsc::channel(1 /* buffer size */);
        let blocking_cancel_channel = self.config.cancel_channel.clone();
        let cancel_forward_handle = Builder::new()
            .name("network-manager cancellation relay".to_string())
            .spawn(move || {
                if let Err(err) = blocking_cancel_channel.recv() {
                    return NetworkManagerError::CancelForwardFailed(err.to_string());
                }
                if let Err(err) = async_cancel_sender.blocking_send(()) {
                    return NetworkManagerError::CancelForwardFailed(err.to_string());
                }

                NetworkManagerError::Cancelled("received cancel signal".to_string())
            })
            .unwrap();
        self.cancellation_relay_handle = Some(cancel_forward_handle);

        // Start up the worker thread
        let peer_id_copy = self.local_peer_id;
        let heartbeat_work_queue = self.config.heartbeat_work_queue.clone();
        let handshake_work_queue = self.config.handshake_work_queue.clone();
        // Take ownership of the work queue and the cluster keypair
        let cluster_keypair = self.config.cluster_keypair.take().unwrap();
        let send_channel = self.config.send_channel.take().unwrap();

        let thread_handle = Builder::new()
            .name("network-manager".to_string())
            .spawn(move || {
                // Block on this to execute the future in a separate thread
                block_on(Self::executor_loop(
                    peer_id_copy,
                    cluster_keypair,
                    swarm,
                    send_channel,
                    heartbeat_work_queue,
                    handshake_work_queue,
                    async_cancel_receiver,
                ))
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
