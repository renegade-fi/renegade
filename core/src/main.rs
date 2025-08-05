//! The entrypoint to the relayer, starts the coordinator thread which manages
//! all other worker threads
#![feature(iter_advance_by)]
#![feature(ip)]
#![feature(let_chains)]
#![allow(incomplete_features)]
#![allow(clippy::redundant_async_block)]
#![deny(unsafe_code)]
#![deny(clippy::missing_docs_in_private_items)]

mod error;
mod setup;

use std::{process::exit, thread, time::Duration};

use api_server::worker::{ApiServer, ApiServerConfig};
use chain_events::listener::{OnChainEventListener, OnChainEventListenerConfig};
use common::worker::{new_worker_failure_channel, watch_worker, Worker};
use common::{default_wrapper::default_option, types::new_cancel_channel};
use constants::{in_bootstrap_mode, VERSION};
use darkpool_client::constants::{BLOCK_POLLING_INTERVAL, EVENT_FILTER_POLLING_INTERVAL};
use darkpool_client::{client::DarkpoolClientConfig, DarkpoolClient};
use event_manager::{manager::EventManager, worker::EventManagerConfig};
use external_api::bus_message::SystemBusMessage;
use gossip_server::{server::GossipServer, worker::GossipServerConfig};
use handshake_manager::{manager::HandshakeManager, worker::HandshakeManagerConfig};
use job_types::handshake_manager::new_handshake_manager_queue;
use job_types::network_manager::new_network_manager_queue;
use job_types::proof_manager::new_proof_manager_queue;
use job_types::task_driver::new_task_driver_queue;
use job_types::{event_manager::new_event_manager_queue, gossip_server::new_gossip_server_queue};
use network_manager::{worker::NetworkManager, worker::NetworkManagerConfig};
use price_reporter::worker::PriceReporterConfig;
use price_reporter::worker::{ExchangeConnectionsConfig, PriceReporter};
use proof_manager::{proof_manager::ProofManager, worker::ProofManagerConfig};
use state::{create_global_state, tui::StateTuiApp};
use system_bus::SystemBus;

use error::CoordinatorError;
use metrics_sampler::setup_metrics_samplers;
use system_clock::SystemClock;
use task_driver::worker::{TaskDriver, TaskDriverConfig};
use tokio::select;
use tracing::info;
use util::err_str;

use crate::setup::node_setup;

/// The amount of time to wait between sending teardown signals and terminating
/// execution
const TERMINATION_TIMEOUT_MS: u64 = 10_000; // 10 seconds

// --------------
// | Entrypoint |
// --------------

/// The entrypoint to the relayer's execution
///
/// At a high level, this method beings a coordinator thread that:
///     1. Allocates resources and starts up workers
///     2. Watches worker threads for panics and errors
///     3. Cleans up and recovers any failed workers that are recoverable
///
/// The general flow for allocating a worker's resources is:
///     1. Allocate any communication primitives the worker needs access to (job
///        queues, global bus, etc)
///     2. Build a cancel channel that the coordinator can use to cancel worker
///        execution
///     3. Allocate and start the worker's execution
///     4. Allocate a thread to monitor the worker for faults
#[tokio::main]
async fn main() -> Result<(), CoordinatorError> {
    // Set the default crypto provider for the process, this will be used by
    // websocket listeners
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // ---------------------
    // | Environment Setup |
    // ---------------------

    // Parse command line arguments
    let args = tokio::task::spawn_blocking(config::parsing::parse_command_line_args)
        .await
        .expect("error blocking on config parse")
        .expect("error parsing command line args");
    let setup_config = args.clone();
    args.configure_telemetry().expect("failed to configure telemetry");
    let min_order_size = args.min_fill_size_decimal_adjusted();

    info!(
        "Relayer running with\n\t version: {}\n\t port: {}\n\t cluster: {:?}",
        VERSION, args.p2p_port, args.cluster_id
    );

    if in_bootstrap_mode() {
        info!("Running in bootstrap mode");
    }

    // Build communication primitives
    // First, the global shared mpmc bus that all workers have access to
    let system_bus = SystemBus::<SystemBusMessage>::new();
    let system_clock = SystemClock::new().await;
    let (network_sender, network_receiver) = new_network_manager_queue();
    let (gossip_worker_sender, gossip_worker_receiver) = new_gossip_server_queue();
    let (handshake_worker_sender, handshake_worker_receiver) = new_handshake_manager_queue();
    let (proof_generation_worker_sender, proof_generation_worker_receiver) =
        new_proof_manager_queue();
    let (task_sender, task_receiver) = new_task_driver_queue();
    let (event_manager_sender, event_manager_receiver) = new_event_manager_queue();

    // Construct a global state
    let (state_failure_send, mut state_failure_recv) = new_worker_failure_channel();
    let global_state = create_global_state(
        &args,
        network_sender.clone(),
        task_sender.clone(),
        handshake_worker_sender.clone(),
        event_manager_sender.clone(),
        system_bus.clone(),
        &system_clock,
        state_failure_send,
    )
    .await?;

    if args.debug {
        // Build the TUI
        let tui = StateTuiApp::new(args.clone(), global_state.clone());

        // Attach a watcher to the TUI and exit the process when the TUI quits
        let join_handle = tui.run();
        thread::spawn(move || {
            #[allow(unused_must_use)]
            {
                join_handle.join();
            }
            exit(0);
        });
    }

    // Construct a darkpool client that workers will use for submitting txs
    let darkpool_client = DarkpoolClient::new(DarkpoolClientConfig {
        darkpool_addr: args.contract_address.clone(),
        chain: args.chain_id,
        rpc_url: args.rpc_url.clone().expect("rpc url not set"),
        private_key: args.private_key.clone(),
        block_polling_interval: BLOCK_POLLING_INTERVAL,
    })
    .map_err(err_str!(CoordinatorError::DarkpoolClient))?;

    // Construct a darkpool client for the on-chain event listener worker
    let chain_listener_darkpool_client = DarkpoolClient::new(DarkpoolClientConfig {
        darkpool_addr: args.contract_address.clone(),
        chain: args.chain_id,
        rpc_url: args.rpc_url.unwrap(),
        private_key: args.private_key.clone(),
        block_polling_interval: EVENT_FILTER_POLLING_INTERVAL,
    })
    .map_err(err_str!(CoordinatorError::DarkpoolClient))?;

    // ----------------
    // | Worker Setup |
    // ----------------

    // --- Node Setup Phase --- //

    // Start the price reporter manager
    let (price_reporter_cancel_sender, price_reporter_cancel_receiver) = new_cancel_channel();
    let (mut price_reporter_manager, price_streams) =
        PriceReporter::new_with_streams(PriceReporterConfig {
            system_bus: system_bus.clone(),
            cancel_channel: price_reporter_cancel_receiver,
            exchange_conn_config: ExchangeConnectionsConfig {
                coinbase_key_name: args.coinbase_key_name,
                coinbase_key_secret: args.coinbase_key_secret,
                eth_websocket_addr: args.eth_websocket_addr.clone(),
            },
            price_reporter_url: args.price_reporter_url,
            disabled: args.disable_price_reporter,
            disabled_exchanges: args.disabled_exchanges,
        });
    price_reporter_manager.start().expect("failed to start price reporter manager");
    let (price_reporter_failure_sender, mut price_reporter_failure_receiver) =
        new_worker_failure_channel();
    watch_worker::<PriceReporter>(&mut price_reporter_manager, &price_reporter_failure_sender);

    // Register metrics samplers
    setup_metrics_samplers(global_state.clone(), &system_clock, price_streams.clone()).await?;

    // Build a task driver that may be used to spawn long-lived asynchronous tasks
    // that are common among workers
    let task_driver_config = TaskDriverConfig::new(
        task_receiver,
        task_sender.clone(),
        darkpool_client.clone(),
        network_sender.clone(),
        proof_generation_worker_sender.clone(),
        event_manager_sender.clone(),
        system_bus.clone(),
        global_state.clone(),
    );
    let mut task_driver =
        TaskDriver::new(task_driver_config).await.expect("failed to build task driver");
    task_driver.start().expect("failed to start task driver");

    let (task_driver_failure_sender, mut task_driver_failure_receiver) =
        new_worker_failure_channel();
    watch_worker::<TaskDriver>(&mut task_driver, &task_driver_failure_sender);

    // Start the proof generation module
    let (proof_manager_cancel_sender, proof_manager_cancel_receiver) = new_cancel_channel();
    let mut proof_manager = ProofManager::new(ProofManagerConfig {
        prover_service_url: args.prover_service_url.clone(),
        prover_service_password: args.prover_service_password.clone(),
        job_queue: proof_generation_worker_receiver,
        cancel_channel: proof_manager_cancel_receiver,
    })
    .await
    .expect("failed to build proof generation module");
    proof_manager.start().expect("failed to start proof generation module");
    let (proof_manager_failure_sender, mut proof_manager_failure_receiver) =
        new_worker_failure_channel();
    watch_worker::<ProofManager>(&mut proof_manager, &proof_manager_failure_sender);

    // Start the network manager
    let (network_cancel_sender, network_cancel_receiver) = new_cancel_channel();
    let network_manager_config = NetworkManagerConfig {
        port: args.p2p_port,
        bind_addr: args.bind_addr,
        known_public_addr: args.public_ip,
        allow_local: args.allow_local,
        cluster_id: args.cluster_id.clone(),
        cluster_keypair: default_option(args.cluster_keypair),
        cluster_symmetric_key: args.cluster_symmetric_key,
        send_channel: default_option(network_receiver),
        gossip_work_queue: gossip_worker_sender.clone(),
        handshake_work_queue: handshake_worker_sender.clone(),
        global_state: global_state.clone(),
        system_bus: system_bus.clone(),
        cancel_channel: network_cancel_receiver,
    };
    let mut network_manager =
        NetworkManager::new(network_manager_config).await.expect("failed to build network manager");
    network_manager.start().expect("failed to start network manager");

    let (network_failure_sender, mut network_failure_receiver) = new_worker_failure_channel();
    watch_worker::<NetworkManager>(&mut network_manager, &network_failure_sender);

    // Start the gossip server
    let (gossip_cancel_sender, gossip_cancel_receiver) = new_cancel_channel();
    let mut gossip_server = GossipServer::new(GossipServerConfig {
        local_peer_id: network_manager.local_peer_id,
        local_addr: network_manager.local_addr.clone(),
        cluster_id: args.cluster_id,
        bootstrap_servers: args.bootstrap_servers,
        darkpool_client: darkpool_client.clone(),
        global_state: global_state.clone(),
        job_sender: gossip_worker_sender.clone(),
        job_receiver: Some(gossip_worker_receiver).into(),
        network_sender: network_sender.clone(),
        cancel_channel: gossip_cancel_receiver,
    })
    .await
    .expect("failed to build gossip server");
    gossip_server.start().expect("failed to start gossip server");
    let (gossip_failure_sender, mut gossip_failure_receiver) = new_worker_failure_channel();
    watch_worker::<GossipServer>(&mut gossip_server, &gossip_failure_sender);

    // Once the minimal set of workers are running, run the setup task
    //
    // This task bootstraps the relayer into a correct raft and sets up the
    // relayer's wallet
    node_setup(&setup_config, task_sender.clone()).await?;

    // Start the event manager
    let (event_manager_cancel_sender, event_manager_cancel_receiver) = new_cancel_channel();
    let mut event_manager = EventManager::new(EventManagerConfig {
        chain: args.chain_id,
        event_export_url: args.event_export_url,
        event_queue: event_manager_receiver,
        cancel_channel: event_manager_cancel_receiver,
    })
    .await
    .expect("failed to build event manager");
    event_manager.start().expect("failed to start event manager");
    let (event_manager_failure_sender, mut event_manager_failure_receiver) =
        new_worker_failure_channel();
    watch_worker::<EventManager>(&mut event_manager, &event_manager_failure_sender);

    // --- Workers Setup Phase --- //

    // Start the handshake manager
    let (handshake_cancel_sender, handshake_cancel_receiver) = new_cancel_channel();
    let mut handshake_manager = HandshakeManager::new(HandshakeManagerConfig {
        min_fill_size: args.min_fill_size,
        state: global_state.clone(),
        network_channel: network_sender.clone(),
        price_streams: price_streams.clone(),
        job_receiver: Some(handshake_worker_receiver),
        job_sender: handshake_worker_sender.clone(),
        task_queue: task_sender.clone(),
        system_bus: system_bus.clone(),
        cancel_channel: handshake_cancel_receiver,
    })
    .await
    .expect("failed to build handshake manager");
    handshake_manager.start().expect("failed to start handshake manager");
    let (handshake_failure_sender, mut handshake_failure_receiver) = new_worker_failure_channel();
    watch_worker::<HandshakeManager>(&mut handshake_manager, &handshake_failure_sender);

    // Start the on-chain event listener
    let (chain_listener_cancel_sender, chain_listener_cancel_receiver) = new_cancel_channel();
    let mut chain_listener = OnChainEventListener::new(OnChainEventListenerConfig {
        websocket_addr: args.eth_websocket_addr,
        darkpool_client: chain_listener_darkpool_client,
        global_state: global_state.clone(),
        handshake_manager_job_queue: handshake_worker_sender.clone(),
        cancel_channel: chain_listener_cancel_receiver,
        event_queue: event_manager_sender.clone(),
    })
    .await
    .expect("failed to build on-chain event listener");
    chain_listener.start().expect("failed to start on-chain event listener");
    let (chain_listener_failure_sender, mut chain_listener_failure_receiver) =
        new_worker_failure_channel();
    watch_worker::<OnChainEventListener>(&mut chain_listener, &chain_listener_failure_sender);

    // Start the API server
    let (api_cancel_sender, api_cancel_receiver) = new_cancel_channel();
    let mut api_server = ApiServer::new(ApiServerConfig {
        http_port: args.http_port,
        websocket_port: args.websocket_port,
        admin_api_key: args.admin_api_key,
        min_transfer_amount: args.min_transfer_amount,
        min_order_size,
        chain: args.chain_id,
        compliance_service_url: args.compliance_service_url.clone(),
        wallet_task_rate_limit: args.wallet_task_rate_limit,
        darkpool_client: darkpool_client.clone(),
        network_sender: network_sender.clone(),
        state: global_state.clone(),
        system_bus,
        price_streams: price_streams.clone(),
        proof_generation_work_queue: proof_generation_worker_sender,
        handshake_manager_work_queue: handshake_worker_sender,
        cancel_channel: api_cancel_receiver,
    })
    .await
    .expect("failed to build api server");
    api_server.start().expect("failed to start api server");
    let (api_failure_sender, mut api_failure_receiver) = new_worker_failure_channel();
    watch_worker::<ApiServer>(&mut api_server, &api_failure_sender);

    // Await module termination, and send a cancel signal for any modules that
    // have been detected to fault
    let recovery_loop = || async {
        loop {
            select! {
                _ = state_failure_recv.recv() => {
                    return Err(CoordinatorError::State("state submodule failed".to_string()));
                },
                _ = task_driver_failure_receiver.recv() => {
                    task_driver = recover_worker(task_driver)?;
                }
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
                _= chain_listener_failure_receiver.recv() => {
                    chain_listener_cancel_sender.send(())
                        .map_err(|err| CoordinatorError::CancelSend(err.to_string()))?;
                    chain_listener = recover_worker(chain_listener)?;
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
                _ = event_manager_failure_receiver.recv() => {
                    event_manager_cancel_sender.send(())
                        .map_err(|err| CoordinatorError::CancelSend(err.to_string()))?;
                    event_manager = recover_worker(event_manager)?;
                }
            };
        }
    };

    // Wait for an error, log the error, and teardown the relayer
    let loop_res: Result<(), CoordinatorError> = recovery_loop().await;
    let err = loop_res.err().unwrap();
    info!("Error in coordinator thread: {:?}", err);

    // Send cancel signals to all workers
    for cancel_channel in [
        network_cancel_sender,
        gossip_cancel_sender,
        handshake_cancel_sender,
        price_reporter_cancel_sender,
        chain_listener_cancel_sender,
        api_cancel_sender,
        proof_manager_cancel_sender,
    ]
    .iter()
    {
        cancel_channel.send(()).unwrap();
    }

    // Give workers time to teardown execution then terminate
    info!("Tearing down workers...");
    thread::sleep(Duration::from_millis(TERMINATION_TIMEOUT_MS));
    info!("Terminating...");

    if args.otlp_enabled {
        opentelemetry::global::shutdown_tracer_provider();
    }
    Err(err)
}

/// Attempt to recover a failed module by cleaning up its resources and
/// re-allocating it
fn recover_worker<W: Worker>(failed_worker: W) -> Result<W, CoordinatorError> {
    if !failed_worker.is_recoverable() {
        return Err(CoordinatorError::Recovery(format!(
            "worker {} is not recoverable",
            failed_worker.name()
        )));
    }

    Ok(failed_worker.recover())
}
