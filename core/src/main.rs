//! The entrypoint to the relayer, starts the coordinator thread which manages all other worker threads
#![feature(let_chains)]
#![feature(generic_const_exprs)]
#![feature(const_likely)]
#![allow(incomplete_features)]
#![deny(unsafe_code)]
#![deny(clippy::missing_docs_in_private_items)]

mod api;
mod api_server;
mod config;
mod error;
mod gossip;
mod handshake;
mod network_manager;
mod price_reporter;
mod proof_generation;
mod state;
mod system_bus;
mod types;
mod worker;

use std::{thread, time::Duration};

use circuits::types::wallet::Wallet;
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
    proof_generation::{proof_manager::ProofManager, worker::ProofManagerConfig},
    state::RelayerState,
    system_bus::SystemBus,
    types::SystemBusMessage,
    worker::{watch_worker, Worker},
};

#[macro_use]
extern crate lazy_static;

/// A type alias for an empty channel used to signal cancellation to workers
pub(crate) type CancelChannel = Receiver<()>;

/// The system-wide value of MAX_BALANCES; the number of allowable balances a wallet holds
pub(crate) const MAX_BALANCES: usize = 5;
/// The system-wide value of MAX_ORDERS; the number of allowable orders a wallet holds
pub(crate) const MAX_ORDERS: usize = 5;
/// The system-wide value of MAX_FEES; the number of allowable fees a wallet holds
pub(crate) const MAX_FEES: usize = 2;
/// The height of the Merkle state tree used by the contract
pub(crate) const MERKLE_HEIGHT: usize = 30;
/// A type wrapper around the wallet type that adds the default generics above
pub(crate) type SizedWallet = Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
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

    // Build communication primitives
    // First, the global shared mpmc bus that all workers have access to
    let system_bus = SystemBus::<SystemBusMessage>::new();
    let (network_sender, network_receiver) = mpsc::unbounded_channel::<GossipOutbound>();
    let (heartbeat_worker_sender, heartbeat_worker_receiver) = channel::unbounded();
    let (handshake_worker_sender, handshake_worker_receiver) = channel::unbounded();
    let (price_reporter_worker_sender, price_reporter_worker_receiver) = channel::unbounded();
    let (proof_generation_worker_sender, proof_generation_worker_receiver) = channel::unbounded();

    // Construct the global state and warm up the config orders by generating proofs of `VALID COMMITMENTS`
    let global_state =
        RelayerState::initialize_global_state(args.debug, args.wallets, args.cluster_id.clone());
    global_state.initialize_order_proofs(proof_generation_worker_sender.clone());

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
        system_bus: system_bus.clone(),
        job_receiver: price_reporter_worker_receiver,
        cancel_channel: price_reporter_cancel_receiver,
        coinbase_api_key: args.coinbase_api_key,
        coinbase_api_secret: args.coinbase_api_secret,
        eth_websocket_addr: args.eth_websocket_addr,
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
        price_reporter_work_queue: price_reporter_worker_sender,
        proof_generation_work_queue: proof_generation_worker_sender,
        cancel_channel: api_cancel_receiver,
    })
    .expect("failed to build api server");
    api_server.start().expect("failed to start api server");
    let (api_failure_sender, mut api_failure_receiver) = mpsc::channel(1 /* buffer_size */);
    watch_worker::<ApiServer>(&mut api_server, api_failure_sender);

    // Start the proof generation module
    let (proof_manager_cancel_sender, proof_manager_cancel_receiver) =
        channel::bounded(1 /* capacity */);
    let mut proof_manager = ProofManager::new(ProofManagerConfig {
        job_queue: proof_generation_worker_receiver,
        cancel_channel: proof_manager_cancel_receiver,
    })
    .expect("failed to build proof generation module");
    proof_manager
        .start()
        .expect("failed to start proof generation module");
    let (proof_manager_failure_sender, mut proof_manager_failure_receiver) =
        mpsc::channel(1 /* buffer_size */);
    watch_worker::<ProofManager>(&mut proof_manager, proof_manager_failure_sender);

    // Hold onto copies of the cancel channels for use at teardown
    let cancel_channels = vec![
        network_cancel_sender.clone(),
        gossip_cancel_sender.clone(),
        handshake_cancel_sender.clone(),
        price_reporter_cancel_sender.clone(),
        api_cancel_sender.clone(),
        proof_manager_cancel_sender.clone(),
    ];

    // For simplicity, we simply cancel all disabled workers, it is simpler to do this than work with
    // a dynamic list of futures
    //
    // We can refactor this decision if it becomes a performance issue
    if args.disable_api_server {
        api_server.cleanup().unwrap();
    }

    if args.disable_price_reporter {
        price_reporter_cancel_sender.send(()).unwrap();
    }

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
                _ = proof_manager_failure_receiver.recv() => {
                    proof_manager_cancel_sender.send(())
                        .map_err(|err| CoordinatorError::CancelSend(err.to_string()))?;
                    proof_manager = recover_worker(proof_manager)?;
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
