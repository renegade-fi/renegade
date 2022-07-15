mod api;
mod composed_protocol;
mod heartbeat_protocol;
mod errors;
mod network_manager;
pub(crate) mod types;

// This file groups logic for the package-public gossip interface
use crossbeam::channel;
use std::{
    collections::HashMap,
    error::Error,
    sync::{
        Arc,
        RwLock
    },
};
use tokio::{
    sync::mpsc::unbounded_channel
};

use crate::{
    gossip::{
        heartbeat_protocol::{
            HeartbeatProtocolExecutor
        },
        types::PeerInfo, network_manager::NetworkManager,
    },
    state::GlobalRelayerState,
};

pub struct GossipServer {
    // Executors
    network_manager: network_manager::NetworkManager,
    heartbeat_executor: heartbeat_protocol::HeartbeatProtocolExecutor,
}

impl GossipServer {
    // Creates a new gossip server
    pub async fn new(
        port: u32,
        bootstrap_servers: Vec<PeerInfo>,
        global_state: GlobalRelayerState
    ) -> Result<Self, Box<dyn Error>> {
        // Build the peer info map
        let mut known_peer_info = HashMap::new();
        for known_peer in bootstrap_servers.iter() {
            println!("Bootstrap server: {:?}", known_peer);
            known_peer_info.insert(known_peer.get_peer_id(), known_peer.clone());
        }
        let known_peers = Arc::new(RwLock::new(known_peer_info));

        // Build the cross-thread channels used to communicate between workers
        let (network_sender, network_receiver) = unbounded_channel();
        let (heartbeat_worker_sender, heatbeat_worker_receiver) = channel::unbounded();

        // Build a network manager to serialize p2p networking requests
        let network_manager = NetworkManager::new(
            port, 
            known_peers.clone(), 
            network_receiver, 
            heartbeat_worker_sender.clone(),
        ).await?;

        // Heartbeat protocol executor; handles sending and receiving heartbeats
        let heartbeat_executor = HeartbeatProtocolExecutor::new(
            network_manager.local_peer_id,
            known_peers.clone(),
            network_sender,
            heartbeat_worker_sender.clone(),
            heatbeat_worker_receiver
        );

        Ok(Self { 
            network_manager,
            heartbeat_executor,
        })
    }

    // Joins execution of calling thread to the execution of the GossipServer's
    // various workers
    pub fn join(self) {
        self.network_manager.join();
        self.heartbeat_executor.join();
    }
}