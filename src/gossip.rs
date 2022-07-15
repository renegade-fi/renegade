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
        // Add boostrap servers to known peers
        {
            let mut locked_global_state = global_state.write().unwrap(); 
            for server in bootstrap_servers.iter() {
                locked_global_state.known_peers.insert(server.get_peer_id(), server.clone());
            }
        } // locked_global_state released

        // Build the cross-thread channels used to communicate between workers
        let (network_sender, network_receiver) = unbounded_channel();
        let (heartbeat_worker_sender, heatbeat_worker_receiver) = channel::unbounded();

        // Build a network manager to serialize p2p networking requests
        let network_manager = NetworkManager::new(
            port, 
            network_receiver, 
            heartbeat_worker_sender.clone(),
            global_state.clone()
        ).await?;

        // After network interface is setup, register self as replicator of owned wallets
        // using the newly created peer information
        {
            let peer_id_copy = network_manager.local_peer_id.clone();
            let global_copy = global_state.clone();
            let mut locked_global_state = global_copy.write().expect("global state lock poisoned");

            for (_, wallet) in locked_global_state.managed_wallets.iter_mut() {
                wallet.metadata.replicas.push(peer_id_copy);
            }
        } // locked_global_state released

        // Heartbeat protocol executor; handles sending and receiving heartbeats
        let heartbeat_executor = HeartbeatProtocolExecutor::new(
            network_manager.local_peer_id,
            network_sender,
            heartbeat_worker_sender.clone(),
            heatbeat_worker_receiver,
            global_state.clone()
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