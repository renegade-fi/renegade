//! The entrypoint to the relayer, starts the coordinator thread which manages all other worker threads
#![deny(unsafe_code)]
#![deny(clippy::missing_docs_in_private_items)]
#![feature(let_chains)]

mod api;
mod api_server;
mod config;
mod error;
mod gossip;
mod handshake;
mod network_manager;
mod price_reporter;
mod state;
mod system_bus;
mod types;
mod worker;

use std::{env, thread, time::Duration};

use crossbeam::channel::{self, Receiver};
use error::CoordinatorError;
use gossip::worker::GossipServerConfig;
use handshake::worker::HandshakeManagerConfig;
use network_manager::worker::NetworkManagerConfig;
use price_reporter::worker::PriceReporterManagerConfig;
use tokio::{select, sync::mpsc};

use crate::{
    api::gossip::GossipOutbound,
    api_server::{server::ApiServer, worker::ApiServerConfig},
    gossip::server::GossipServer,
    handshake::manager::HandshakeManager,
    network_manager::manager::NetworkManager,
    price_reporter::manager::PriceReporterManager,
    state::RelayerState,
    system_bus::SystemBus,
    types::SystemBusMessage,
    worker::{watch_worker, Worker},
};

#[macro_use]
extern crate lazy_static;

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
        args.version, args.p2p_port, args.cluster_id
    );

    // Load secrets.env and validate that expected environment variables exist
    dotenv::from_filename("secrets.env").expect("Cannot read secrets from secrets.env");
    let required_env_variables = [
        "COINBASE_API_KEY",
        "COINBASE_API_SECRET",
        "ETHEREUM_MAINNET_WSS",
    ];
    for env_variable in required_env_variables {
        env::var(env_variable).unwrap_or_else(|_| {
            panic!(
                "Could not find environment variable {} in secrets.env",
                env_variable,
            )
        });
    }

    // Construct the global state
    let global_state =
        RelayerState::initialize_global_state(args.debug, args.wallets, args.cluster_id.clone());

    // Build communication primitives
    // First, the global shared mpmc bus that all workers have access to
    let system_bus = SystemBus::<SystemBusMessage>::new();
    let (network_sender, network_receiver) = mpsc::unbounded_channel::<GossipOutbound>();
    let (heartbeat_worker_sender, heartbeat_worker_receiver) = channel::unbounded();
    let (handshake_worker_sender, handshake_worker_receiver) = channel::unbounded();
    let (price_reporter_worker_sender, price_reporter_worker_receiver) = channel::unbounded();

    // Start the network manager
    let (network_cancel_sender, network_cancel_receiver) = channel::bounded(1 /* capacity */);
    let network_manager_config = NetworkManagerConfig {
        port: args.p2p_port,
        cluster_id: args.cluster_id.clone(),
        cluster_keypair: Some(args.cluster_keypair),
        send_channel: Some(network_receiver),
        heartbeat_work_queue: heartbeat_worker_sender.clone(),
        handshake_work_queue: handshake_worker_sender,
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
        global_state: global_state.clone(),
        network_channel: network_sender,
        job_receiver: handshake_worker_receiver,
        system_bus: system_bus.clone(),
        cancel_channel: handshake_cancel_receiver,
    })
    .expect("failed to build handshake manager");
    handshake_manager
        .start()
        .expect("failed to start handshake manager");
    let (handshake_failure_sender, mut handshake_failure_receiver) =
        mpsc::channel(1 /* buffer size */);
    watch_worker::<HandshakeManager>(&mut handshake_manager, handshake_failure_sender);

    // Start the price reporter manager
    let (price_reporter_cancel_sender, price_reporter_cancel_receiver) =
        channel::bounded(1 /* capacity */);
    let mut price_reporter_manager = PriceReporterManager::new(PriceReporterManagerConfig {
        job_receiver: price_reporter_worker_receiver,
        cancel_channel: price_reporter_cancel_receiver,
    })
    .expect("failed to build price reporter manager");
    price_reporter_manager
        .start()
        .expect("failed to start price reporter manager");
    let (price_reporter_failure_sender, mut price_reporter_failure_receiver) =
        mpsc::channel(1 /* buffer size */);
    watch_worker::<PriceReporterManager>(
        &mut price_reporter_manager,
        price_reporter_failure_sender,
    );

    // Start the API server
    let (api_cancel_sender, api_cancel_receiver) = channel::bounded(1 /* capacity */);
    let mut api_server = ApiServer::new(ApiServerConfig {
        http_port: args.http_port,
        websocket_port: args.websocket_port,
        global_state: global_state.clone(),
        system_bus,
        cancel_channel: api_cancel_receiver,
    })
    .expect("failed to build api server");
    api_server.start().expect("failed to start api server");
    let (api_failure_sender, mut api_failure_receiver) = mpsc::channel(1 /* buffer_size */);
    watch_worker::<ApiServer>(&mut api_server, api_failure_sender);

    // Hold onto copies of the cancel channels for use at teardown
    let cancel_channels = vec![
        network_cancel_sender.clone(),
        gossip_cancel_sender.clone(),
        handshake_cancel_sender.clone(),
        price_reporter_cancel_sender.clone(),
        api_cancel_sender.clone(),
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
                _ = price_reporter_failure_receiver.recv() => {
                    price_reporter_cancel_sender.send(())
                        .map_err(|err| CoordinatorError::CancelSend(err.to_string()))?;
                    price_reporter_manager = recover_worker(price_reporter_manager)?;
                }
                _ = api_failure_receiver.recv() => {
                    api_cancel_sender.send(())
                        .map_err(|err| CoordinatorError::CancelSend(err.to_string()))?;
                    api_server = recover_worker(api_server)?;
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
