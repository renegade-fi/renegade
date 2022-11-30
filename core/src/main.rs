//! The entrypoint to the relayer, starts the coordinator thread which manages all other worker threads
#![deny(unsafe_code)]
#![deny(missing_docs)]

mod api;
mod config;
mod gossip;
mod handshake;
mod network_manager;
mod state;
mod worker;

use crossbeam::channel;
use gossip::worker::GossipServerConfig;
use network_manager::worker::NetworkManagerConfig;
use std::error::Error;
use tokio::sync::{mpsc, oneshot};

use crate::{
    api::gossip::GossipOutbound,
    gossip::server::GossipServer,
    handshake::manager::HandshakeManager,
    network_manager::manager::NetworkManager,
    state::RelayerState,
    worker::{watch_worker, Worker},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Parse command line arguments
    let args = config::parse_command_line_args().expect("error parsing command line args");
    println!(
        "Relayer running with\n\t version: {}\n\t port: {}",
        args.version, args.port
    );

    // Construct the global state
    let global_state =
        RelayerState::initialize_global_state(args.wallet_ids, args.bootstrap_servers);

    // Build communication primitives
    let (network_sender, network_receiver) = mpsc::unbounded_channel::<GossipOutbound>();
    let (heartbeat_worker_sender, heartbeat_worker_receiver) = channel::unbounded();
    let (handshake_worker_sender, handshake_worker_receiver) = channel::unbounded();

    // Start the network manager
    let mut network_manager = NetworkManager::new(NetworkManagerConfig {
        port: args.port,
        send_channel: Some(network_receiver),
        heartbeat_work_queue: heartbeat_worker_sender.clone(),
        handshake_work_queue: handshake_worker_sender,
        global_state: global_state.clone(),
    })
    .expect("failed to build network manager");
    network_manager
        .start()
        .expect("failed to start network manager");

    // Watch the thread
    let (network_failure_sender, network_failure_receiver) = oneshot::channel();
    watch_worker::<NetworkManager>(network_manager.join(), network_failure_sender);

    // Start the gossip server
    let mut gossip_server = GossipServer::new(GossipServerConfig {
        local_peer_id: network_manager.local_peer_id,
        global_state: global_state.clone(),
        heartbeat_worker_sender,
        heartbeat_worker_receiver,
        network_sender: network_sender.clone(),
    })
    .expect("failed to build gossip server");
    gossip_server
        .start()
        .expect("failed to start gossip server");
    let (gossip_failure_sender, gossip_failure_receiver) = oneshot::channel();
    watch_worker::<GossipServer>(gossip_server.join(), gossip_failure_sender);

    // Start the handshake manager
    let handshake_manager =
        HandshakeManager::new(global_state, network_sender, handshake_worker_receiver);

    // Await termination of the submodules
    handshake_manager.join().unwrap();
    network_failure_receiver.blocking_recv().unwrap();
    gossip_failure_receiver.blocking_recv().unwrap();

    // Unreachable
    Ok(())
}
