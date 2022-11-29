//! The entrypoint to the relayer, starts the coordinator thread which manages all other worker threads

#![deny(unsafe_code, missing_docs)]

mod api;
mod config;
mod gossip;
mod handshake;
mod network_manager;
mod state;
mod worker;

use crossbeam::channel;
use std::error::Error;
use tokio::sync::mpsc;

use crate::{
    api::gossip::GossipOutbound, gossip::server::GossipServer,
    handshake::manager::HandshakeManager, network_manager::manager::NetworkManager,
    state::RelayerState,
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
    let network_manager = NetworkManager::new(
        args.port,
        network_receiver,
        heartbeat_worker_sender.clone(),
        handshake_worker_sender.clone(),
        global_state.clone(),
    )
    .await
    .expect("error building network manager");

    // Start the gossip server
    let gossip_server = GossipServer::new(
        network_manager.local_peer_id,
        global_state.clone(),
        heartbeat_worker_sender.clone(),
        heartbeat_worker_receiver,
        network_sender.clone(),
    )
    .await
    .unwrap();

    // Start the handshake manager
    let handshake_manager = HandshakeManager::new(
        global_state.clone(),
        network_sender.clone(),
        handshake_worker_receiver,
    );

    // Await termination of the submodules
    network_manager.join().unwrap();
    gossip_server.join().unwrap();
    handshake_manager.join().unwrap();

    // Unreachable
    Ok(())
}
