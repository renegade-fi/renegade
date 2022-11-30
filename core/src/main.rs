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
use handshake::worker::HandshakeManagerConfig;
use network_manager::worker::NetworkManagerConfig;
use std::error::Error;
use tokio::sync::mpsc;

use crate::{
    api::gossip::GossipOutbound,
    gossip::server::GossipServer,
    handshake::manager::HandshakeManager,
    network_manager::manager::NetworkManager,
    state::RelayerState,
    worker::{watch_worker, Worker},
};

/// The entrypoint to the relayer's execution
///
/// At a high level, this method beings a coordinator thread that:
///     1. Allocates resources and starts up workers
///     2. Watches worker threads for panics and errors
///     3. Cleans up and recovers any failed workers that are recoverable
///
/// The general flow for allocating a worker's resources is:
///     1. Allocate any communication primitives the worker needs access to (job queues, global bus, etc)
///     2. Build a cancel channel that the coordinator can use to cancel worker execution
///     3. Allocate and start the worker's execution
///     4. Allocate a thread to monitor the worker for faults
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
    let (network_cancel_sender, network_cancel_receiver) = channel::bounded(1 /* capacity */);
    let mut network_manager = NetworkManager::new(NetworkManagerConfig {
        port: args.port,
        send_channel: Some(network_receiver),
        heartbeat_work_queue: heartbeat_worker_sender.clone(),
        handshake_work_queue: handshake_worker_sender,
        global_state: global_state.clone(),
        cancel_channel: network_cancel_receiver,
    })
    .expect("failed to build network manager");
    network_manager
        .start()
        .expect("failed to start network manager");

    let (network_failure_sender, mut network_failure_receiver) =
        mpsc::channel(1 /* buffer size */);
    watch_worker::<NetworkManager>(&mut network_manager, network_failure_sender);

    // Start the gossip server
    let (gossip_cancel_sender, gossip_cancel_receiver) = channel::bounded(1 /* capacity */);
    let mut gossip_server = GossipServer::new(GossipServerConfig {
        local_peer_id: network_manager.local_peer_id,
        global_state: global_state.clone(),
        heartbeat_worker_sender,
        heartbeat_worker_receiver,
        network_sender: network_sender.clone(),
        cancel_channel: gossip_cancel_receiver,
    })
    .expect("failed to build gossip server");
    gossip_server
        .start()
        .expect("failed to start gossip server");
    let (gossip_failure_sender, mut gossip_failure_receiver) =
        mpsc::channel(1 /* buffer size */);
    watch_worker::<GossipServer>(&mut gossip_server, gossip_failure_sender);

    // Start the handshake manager
    let (handshake_cancel_sender, handshake_cancel_receiver) =
        channel::bounded(1 /* capacity */);
    let mut handshake_manager = HandshakeManager::new(HandshakeManagerConfig {
        global_state,
        network_channel: network_sender,
        job_receiver: handshake_worker_receiver,
        cancel_channel: handshake_cancel_receiver,
    })
    .expect("failed to build handshake manager");
    handshake_manager
        .start()
        .expect("failed to start handshake manager");
    let (handshake_failure_sender, mut handshake_failure_receiver) =
        mpsc::channel(1 /* buffer size */);
    watch_worker::<HandshakeManager>(&mut handshake_manager, handshake_failure_sender);

    // Await termination of the submodules
    network_failure_receiver.recv().await.unwrap();
    gossip_failure_receiver.recv().await.unwrap();
    handshake_failure_receiver.recv().await.unwrap();

    // Unreachable
    Ok(())
}
