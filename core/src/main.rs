//! The entrypoint to the relayer, starts the coordinator thread which manages all other worker threads
#![deny(unsafe_code)]
#![deny(clippy::missing_docs_in_private_items)]
#![feature(let_chains)]

mod api;
mod config;
mod error;
mod gossip;
mod handshake;
mod network_manager;
mod state;
mod types;
mod worker;

use std::{thread, time::Duration};

use crossbeam::channel::{self, Receiver};
use error::CoordinatorError;
use gossip::worker::GossipServerConfig;
use handshake::worker::HandshakeManagerConfig;
use network_manager::worker::NetworkManagerConfig;
use tokio::{select, sync::mpsc};

use crate::{
    api::gossip::GossipOutbound,
    gossip::server::GossipServer,
    handshake::manager::HandshakeManager,
    network_manager::manager::NetworkManager,
    state::RelayerState,
    worker::{watch_worker, Worker},
};

/// A type alias for an empty channel used to signal cancellation to workers
pub(crate) type CancelChannel = Receiver<()>;

/// The amount of time to wait between sending teardown signals and terminating execution
const TERMINATION_TIMEOUT_MS: u64 = 10_000; // 10 seconds

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
async fn main() -> Result<(), CoordinatorError> {
    // Parse command line arguments
    let args = config::parse_command_line_args().expect("error parsing command line args");
    println!(
        "Relayer running with\n\t version: {}\n\t port: {}\n\t cluster: {:?}",
        args.version, args.port, args.cluster_id
    );

    // Construct the global state
    let global_state =
        RelayerState::initialize_global_state(args.debug, args.wallet_ids, args.cluster_id.clone());

    // Build communication primitives
    // First, the global shared mpmc bus that all workers have access to
    let (system_bus_sender, system_bus_receiver) = channel::unbounded();
    let (network_sender, network_receiver) = mpsc::unbounded_channel::<GossipOutbound>();
    let (heartbeat_worker_sender, heartbeat_worker_receiver) = channel::unbounded();
    let (handshake_worker_sender, handshake_worker_receiver) = channel::unbounded();

    // Start the network manager
    let (network_cancel_sender, network_cancel_receiver) = channel::bounded(1 /* capacity */);
    let network_manager_config = NetworkManagerConfig {
        port: args.port,
        cluster_id: args.cluster_id.clone(),
        cluster_keypair: Some(args.cluster_keypair),
        send_channel: Some(network_receiver),
        heartbeat_work_queue: heartbeat_worker_sender.clone(),
        handshake_work_queue: handshake_worker_sender,
        system_bus_sender: system_bus_sender.clone(),
        system_bus_receiver: system_bus_receiver.clone(),
        global_state: global_state.clone(),
        cancel_channel: network_cancel_receiver,
    };
    let mut network_manager =
        NetworkManager::new(network_manager_config).expect("failed to build network manager");
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
        local_addr: network_manager.local_addr.clone(),
        cluster_id: args.cluster_id,
        bootstrap_servers: args.bootstrap_servers,
        global_state: global_state.clone(),
        heartbeat_worker_sender,
        heartbeat_worker_receiver,
        network_sender: network_sender.clone(),
        system_bus_sender: system_bus_sender.clone(),
        system_bus_receiver: system_bus_receiver.clone(),
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
        system_bus_sender,
        system_bus_receiver,
        cancel_channel: handshake_cancel_receiver,
    })
    .expect("failed to build handshake manager");
    handshake_manager
        .start()
        .expect("failed to start handshake manager");
    let (handshake_failure_sender, mut handshake_failure_receiver) =
        mpsc::channel(1 /* buffer size */);
    watch_worker::<HandshakeManager>(&mut handshake_manager, handshake_failure_sender);

    // Hold onto copies of the cancel channels for use at teardown
    let cancel_channels = vec![
        network_cancel_sender.clone(),
        gossip_cancel_sender.clone(),
        handshake_cancel_sender.clone(),
    ];

    // Await module termination, and send a cancel signal for any modules that
    // have been detected to fault
    let recovery_loop = || async move {
        loop {
            select! {
                _ = network_failure_receiver.recv() => {
                    network_cancel_sender.send(())
                        .map_err(|err| CoordinatorError::CancelSend(err.to_string()))?;
                    network_manager = recover_worker(network_manager)?;
                }
                _ = gossip_failure_receiver.recv() => {
                    gossip_cancel_sender.send(())
                        .map_err(|err| CoordinatorError::CancelSend(err.to_string()))?;
                    gossip_server = recover_worker(gossip_server)?;
                }
                _ = handshake_failure_receiver.recv() => {
                    handshake_cancel_sender.send(())
                        .map_err(|err| CoordinatorError::CancelSend(err.to_string()))?;
                    handshake_manager = recover_worker(handshake_manager)?;
                }
            };
        }
    };

    // Wait for an error, log the error, and teardown the relayer
    let loop_res: Result<(), CoordinatorError> = recovery_loop().await;
    let err = loop_res.err().unwrap();
    println!("Error in coordinator thread: {:?}", err);

    // Send cancel signals to all workers
    for cancel_channel in cancel_channels.iter() {
        #[allow(unused_must_use)]
        cancel_channel.send(());
    }

    // Give workers time to teardown execution then terminate
    println!("Tearing down workers...");
    thread::sleep(Duration::from_millis(TERMINATION_TIMEOUT_MS));
    println!("Terminating...");

    Err(err)
}

/// Attempt to recover a failed module by cleaning up its resources and re-allocating it
fn recover_worker<W: Worker>(failed_worker: W) -> Result<W, CoordinatorError> {
    if !failed_worker.is_recoverable() {
        return Err(CoordinatorError::Recovery(format!(
            "worker {} is not recoverable",
            failed_worker.name()
        )));
    }

    Ok(failed_worker.recover())
}
