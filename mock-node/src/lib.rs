//! Defines mock node methods for integration testing

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![allow(incomplete_features)]

use std::mem;

use api_server::worker::{ApiServer, ApiServerConfig};
use chain_events::listener::{OnChainEventListener, OnChainEventListenerConfig};
use common::{
    default_wrapper::{DefaultOption, default_option},
    types::price::Price,
    worker::{Worker, new_worker_failure_channel},
};
use config::RelayerConfig;
use darkpool_client::{
    DarkpoolClient, client::DarkpoolClientConfig, constants::BLOCK_POLLING_INTERVAL,
};
use ed25519_dalek::Keypair;
use external_api::bus_message::SystemBusMessage;
use eyre::Result;
use futures::Future;
use gossip_server::{server::GossipServer, worker::GossipServerConfig};
use handshake_manager::{manager::HandshakeManager, worker::HandshakeManagerConfig};
use job_types::{
    event_manager::{EventManagerQueue, EventManagerReceiver, new_event_manager_queue},
    gossip_server::{
        GossipServerJob, GossipServerQueue, GossipServerReceiver, new_gossip_server_queue,
    },
    handshake_manager::{
        HandshakeManagerJob, HandshakeManagerQueue, HandshakeManagerReceiver,
        new_handshake_manager_queue,
    },
    network_manager::{
        NetworkManagerJob, NetworkManagerQueue, NetworkManagerReceiver, new_network_manager_queue,
    },
    price_reporter::{
        PriceReporterJob, PriceReporterQueue, PriceReporterReceiver, new_price_reporter_queue,
    },
    proof_manager::{
        ProofManagerJob, ProofManagerQueue, ProofManagerReceiver, new_proof_manager_queue,
    },
    task_driver::{TaskDriverJob, TaskDriverQueue, TaskDriverReceiver, new_task_driver_queue},
};
use libp2p::Multiaddr;
use network_manager::worker::{NetworkManager, NetworkManagerConfig};
use price_reporter::{
    mock::{MockPriceReporter, setup_mock_token_remap},
    worker::{ExchangeConnectionsConfig, PriceReporter, PriceReporterConfig},
};
use proof_manager::{
    mock::MockProofManager, proof_manager::ProofManager, worker::ProofManagerConfig,
};
use reqwest::{Client, Method, Response, header::HeaderMap};
use serde::{Serialize, de::DeserializeOwned};
use state::{State, create_global_state};
use system_bus::SystemBus;
use system_clock::SystemClock;
use task_driver::worker::{TaskDriver, TaskDriverConfig};
use test_helpers::mocks::mock_cancel;
use tokio::runtime::Handle;

/// A helper that creates a dummy runtime and blocks a task on it
///
/// We use this to give a synchronous mock node api, which emits a convenient
/// builder pattern
fn run_fut<F>(fut: F) -> F::Output
where
    F: Future,
{
    Handle::current().block_on(fut)
}

/// The mock node struct, used to build testing nodes
///
/// We store both ends of the queue for each worker because:
///   1. Storing the sender allows testing code to send messages to the worker
///      directly
///   2. Storing the receiver prevents the receiver from being dropped, which
///      would close the channel. We want the channel to remain open even if no
///      worker is listening
///
/// The receiver end of each queue is stored in a `DefaultOption` so that
/// if/when a worker is spawned for that queue they may take ownership of the
/// receiver.
#[derive(Clone)]
pub struct MockNodeController {
    /// The local addr that the relayer has bound to
    local_addr: Multiaddr,
    /// The relayer's config
    config: RelayerConfig,

    // --- Shared Handles --- //
    /// The darkpool client
    darkpool_client: Option<DarkpoolClient>,
    /// The system bus
    bus: SystemBus<SystemBusMessage>,
    /// The system clock
    clock: SystemClock,
    /// The global state (if initialized)
    state: Option<State>,
    /// HTTP client for API requests
    http_client: Client,

    // --- Worker Queues --- //
    /// The network manager's queue
    network_queue: (NetworkManagerQueue, DefaultOption<NetworkManagerReceiver>),
    /// The gossip message queue
    gossip_queue: (GossipServerQueue, DefaultOption<GossipServerReceiver>),
    /// The handshake manager's queue
    handshake_queue: (HandshakeManagerQueue, DefaultOption<HandshakeManagerReceiver>),
    /// The price reporter's queue
    price_queue: (PriceReporterQueue, DefaultOption<PriceReporterReceiver>),
    /// The proof generation queue
    proof_queue: (ProofManagerQueue, DefaultOption<ProofManagerReceiver>),
    /// The event manager queue
    event_queue: (EventManagerQueue, DefaultOption<EventManagerReceiver>),
    /// The task manager queue
    task_queue: (TaskDriverQueue, DefaultOption<TaskDriverReceiver>),
}

/// All methods use a builder pattern to allow chained construction
impl MockNodeController {
    /// Constructor
    pub fn new(config: RelayerConfig) -> Self {
        let bus = SystemBus::new();
        let clock = run_fut(SystemClock::new());
        let (network_sender, network_recv) = new_network_manager_queue();
        let (gossip_sender, gossip_recv) = new_gossip_server_queue();
        let (handshake_send, handshake_recv) = new_handshake_manager_queue();
        let (price_sender, price_recv) = new_price_reporter_queue();
        let (proof_gen_sender, proof_gen_recv) = new_proof_manager_queue();
        let (event_sender, event_recv) = new_event_manager_queue();
        let (task_sender, task_recv) = new_task_driver_queue();

        Self {
            config,
            local_addr: Multiaddr::empty(),
            darkpool_client: None,
            bus,
            clock,
            state: None,
            network_queue: (network_sender, default_option(network_recv)),
            gossip_queue: (gossip_sender, default_option(gossip_recv)),
            handshake_queue: (handshake_send, default_option(handshake_recv)),
            price_queue: (price_sender, default_option(price_recv)),
            proof_queue: (proof_gen_sender, default_option(proof_gen_recv)),
            event_queue: (event_sender, default_option(event_recv)),
            task_queue: (task_sender, default_option(task_recv)),
            http_client: Client::new(),
        }
    }

    /// A helper to clone the cluster keypair out of the config for workers
    ///
    /// The keypair type doesn't have a `Clone` method for safety so this
    /// workaround is necessary
    fn clone_cluster_key(&self) -> Keypair {
        let key_bytes = self.config.cluster_keypair.to_bytes();
        Keypair::from_bytes(&key_bytes).expect("Failed to clone cluster keypair")
    }

    // -----------
    // | Getters |
    // -----------

    /// Get a copy of the relayer config
    pub fn config(&self) -> RelayerConfig {
        self.config.clone()
    }

    /// Get a copy of the global state
    ///
    /// Panics if the state is not initialized
    pub fn state(&self) -> State {
        self.state.clone().expect("State not initialized")
    }

    /// Get a handle to the darkpool client
    pub fn darkpool_client(&self) -> DarkpoolClient {
        self.darkpool_client.clone().expect("Darkpool client not initialized")
    }

    /// Get a copy of the system bus
    pub fn bus(&self) -> SystemBus<SystemBusMessage> {
        self.bus.clone()
    }

    // -----------------
    // | Worker Queues |
    // -----------------

    /// Send an API request to the mock node
    #[allow(clippy::needless_pass_by_value)]
    pub async fn send_api_req<B: Serialize, R: DeserializeOwned>(
        &self,
        route: &str,
        method: Method,
        headers: HeaderMap,
        body: B,
    ) -> Result<R> {
        let resp = self.send_api_req_raw(route, method, headers, body).await?;
        if resp.status().is_success() {
            resp.json().await.map_err(|e| eyre::eyre!(e))
        } else {
            Err(eyre::eyre!("Request failed with status: {}", resp.status()))
        }
    }

    /// Send an API request to the mock node and return the raw response
    pub async fn send_api_req_raw<B: Serialize>(
        &self,
        route: &str,
        method: Method,
        headers: HeaderMap,
        body: B,
    ) -> Result<Response> {
        let client = &self.http_client;
        let url = format!("http://localhost:{}{}", self.config.http_port, route);

        match method {
            Method::GET => {
                client.get(url).headers(headers).send().await.map_err(|e| eyre::eyre!(e))
            },
            Method::POST => client
                .post(url)
                .headers(headers)
                .json(&body)
                .send()
                .await
                .map_err(|e| eyre::eyre!(e)),
            _ => eyre::bail!("Unsupported method"),
        }
    }

    /// Send a job to the task driver
    pub fn send_task_job(&self, job: TaskDriverJob) -> Result<()> {
        self.task_queue.0.send(job).map_err(|e| eyre::eyre!(e))
    }

    /// Send a job to the network manager
    pub fn send_network_job(&self, job: NetworkManagerJob) -> Result<()> {
        self.network_queue.0.send(job).map_err(|e| eyre::eyre!(e))
    }

    /// Send a job to the gossip server
    pub fn send_gossip_job(&self, job: GossipServerJob) -> Result<()> {
        self.gossip_queue.0.send(job).map_err(|e| eyre::eyre!(e))
    }

    /// Send a job to the handshake manager
    pub fn send_handshake_job(&self, job: HandshakeManagerJob) -> Result<()> {
        self.handshake_queue.0.send(job).map_err(|e| eyre::eyre!(e))
    }

    /// Send a job to the price reporter
    pub fn send_price_reporter_job(&self, job: PriceReporterJob) -> Result<()> {
        self.price_queue.0.send(job).map_err(|e| eyre::eyre!(e))
    }

    /// Send a job to the proof manager
    pub fn send_proof_job(&self, job: ProofManagerJob) -> Result<()> {
        self.proof_queue.0.send(job).map_err(|e| eyre::eyre!(e))
    }

    // -----------
    // | Setters |
    // -----------

    /// Clear the state of the mock node
    ///
    /// This will clear the configured tables as well as all snapshots created
    /// by the raft
    pub async fn clear_state(&mut self, tables: &[&str]) -> Result<()> {
        self.clear_raft_snapshots().await?;
        for table in tables {
            self.clear_table(table)?;
        }

        Ok(())
    }

    /// Clear a table on the state's database
    fn clear_table(&self, name: &str) -> Result<()> {
        let db = &self.state().db;
        let tx = db.new_write_tx()?;

        tx.clear_table(name)?;
        tx.commit()?;
        Ok(())
    }

    /// Delete any snapshots the raft has taken
    async fn clear_raft_snapshots(&self) -> Result<()> {
        let snapshot_path = self.config().raft_snapshot_path;
        clear_dir_contents(&snapshot_path).await
    }

    // -------------------
    // | Builder Methods |
    // -------------------

    /// Add a darkpool client to the mock node
    pub fn with_darkpool_client(mut self) -> Self {
        let conf = DarkpoolClientConfig {
            darkpool_addr: self.config.contract_address.clone(),
            chain: self.config.chain_id,
            rpc_url: self.config.rpc_url.clone().unwrap(),
            private_key: self.config.relayer_wallet_key().clone(),
            block_polling_interval: BLOCK_POLLING_INTERVAL,
        };

        // Expects to be running in a Tokio runtime
        let client = DarkpoolClient::new(conf).expect("Failed to create darkpool client");
        self.darkpool_client = Some(client);

        self
    }

    /// Add a global state instance to the mock node
    pub fn with_state(mut self) -> Self {
        // Create a global state instance
        let network_queue = self.network_queue.0.clone();
        let task_sender = self.task_queue.0.clone();
        let handshake_queue = self.handshake_queue.0.clone();
        let event_queue = self.event_queue.0.clone();
        let bus = self.bus.clone();
        let clock = self.clock.clone();
        let (failure_send, failure_recv) = new_worker_failure_channel();

        let state = run_fut(create_global_state(
            &self.config,
            network_queue,
            task_sender,
            handshake_queue,
            event_queue,
            bus,
            &clock,
            failure_send,
        ))
        .expect("Failed to create state instance");
        std::mem::forget(failure_recv); // forget to avoid closing

        self.state = Some(state);
        self
    }

    /// Add a task driver to the mock node
    pub fn with_task_driver(mut self) -> Self {
        let task_queue = self.task_queue.1.take().unwrap();
        let task_sender = self.task_queue.0.clone();
        let darkpool_client =
            self.darkpool_client.clone().expect("Darkpool client not initialized");
        let network_queue = self.network_queue.0.clone();
        let proof_queue = self.proof_queue.0.clone();
        let event_queue = self.event_queue.0.clone();
        let bus = self.bus.clone();
        let state = self.state.clone().expect("State not initialized");

        let conf = TaskDriverConfig::new(
            task_queue,
            task_sender,
            darkpool_client,
            network_queue,
            proof_queue,
            event_queue,
            bus,
            state,
        );
        let mut driver = run_fut(TaskDriver::new(conf)).expect("Failed to create task driver");
        driver.start().expect("Failed to start task driver");

        self
    }

    /// Add a network manager to the mock node
    pub fn with_network_manager(mut self) -> Self {
        let config = &self.config;
        let network_recv = self.network_queue.1.take().unwrap();
        let gossip_sender = self.gossip_queue.0.clone();
        let handshake_send = self.handshake_queue.0.clone();
        let cancel_channel = mock_cancel();

        let conf = NetworkManagerConfig {
            port: config.p2p_port,
            bind_addr: config.bind_addr,
            known_public_addr: config.public_ip,
            allow_local: config.allow_local,
            cluster_id: config.cluster_id.clone(),
            cluster_keypair: default_option(self.clone_cluster_key()),
            cluster_symmetric_key: self.config.cluster_symmetric_key,
            send_channel: default_option(network_recv),
            gossip_work_queue: gossip_sender,
            handshake_work_queue: handshake_send,
            system_bus: self.bus.clone(),
            global_state: self.state.clone().expect("State not initialized"),
            cancel_channel,
        };
        let mut manager =
            run_fut(NetworkManager::new(conf)).expect("Failed to create network manager");
        manager.start().expect("Failed to start network manager");

        // Set the local addr after the manager binds to it
        self.local_addr = manager.local_addr;
        self
    }

    /// Add a gossip server to the mock node
    pub fn with_gossip_server(mut self) -> Self {
        let config = &self.config;
        let state = self.state.clone().expect("State not initialized");
        let local_peer_id = run_fut(state.get_peer_id()).expect("Failed to get peer id");
        let darkpool_client =
            self.darkpool_client.clone().expect("Darkpool client not initialized");

        let job_sender = self.gossip_queue.0.clone();
        let job_receiver = self.gossip_queue.1.take().unwrap();
        let network_sender = self.network_queue.0.clone();
        let cancel_channel = mock_cancel();

        let conf = GossipServerConfig {
            local_peer_id,
            local_addr: self.local_addr.clone(),
            cluster_id: config.cluster_id.clone(),
            bootstrap_servers: config.bootstrap_servers.clone(),
            darkpool_client,
            global_state: state,
            job_sender,
            job_receiver: default_option(job_receiver),
            network_sender,
            cancel_channel,
        };
        let mut server = run_fut(GossipServer::new(conf)).expect("Failed to create gossip server");
        server.start().expect("Failed to start gossip server");

        self
    }

    /// Add a handshake manager to the mock node
    pub fn with_handshake_manager(mut self) -> Self {
        let state = self.state.clone().expect("State not initialized");
        let network_channel = self.network_queue.0.clone();
        let price_reporter_job_queue = self.price_queue.0.clone();
        let job_sender = self.handshake_queue.0.clone();
        let job_receiver = self.handshake_queue.1.take().unwrap();
        let cancel_channel = mock_cancel();
        let system_bus = self.bus.clone();
        let task_queue = self.task_queue.0.clone();

        let conf = HandshakeManagerConfig {
            min_fill_size: self.config.min_fill_size,
            state,
            network_channel,
            price_reporter_job_queue,
            job_sender,
            job_receiver: Some(job_receiver),
            task_queue,
            system_bus,
            cancel_channel,
        };
        let mut manager =
            run_fut(HandshakeManager::new(conf)).expect("Failed to create handshake manager");
        manager.start().expect("Failed to start handshake manager");

        self
    }

    /// Add a price reporter to the mock node
    pub fn with_price_reporter(mut self) -> Self {
        let config = &self.config;
        let job_receiver = self.price_queue.1.take().unwrap();
        let cancel_channel = mock_cancel();
        let system_bus = self.bus.clone();

        let conf = PriceReporterConfig {
            exchange_conn_config: ExchangeConnectionsConfig {
                coinbase_key_name: config.coinbase_key_name.clone(),
                coinbase_key_secret: config.coinbase_key_secret.clone(),
                eth_websocket_addr: config.eth_websocket_addr.clone(),
            },
            price_reporter_url: config.price_reporter_url.clone(),
            disabled: config.disable_price_reporter,
            disabled_exchanges: config.disabled_exchanges.clone(),
            job_receiver: default_option(job_receiver),
            system_bus,
            cancel_channel,
        };
        let mut reporter =
            run_fut(PriceReporter::new(conf)).expect("Failed to create price reporter");
        reporter.start().expect("Failed to start price reporter");

        self
    }

    /// Add a mock price reporter to the mock node
    pub fn with_mock_price_reporter(mut self, price: Price) -> Self {
        let job_queue = self.price_queue.1.take().unwrap();
        let reporter = MockPriceReporter::new(price, job_queue);
        reporter.run();

        // Setup a mock token map
        setup_mock_token_remap();
        self
    }

    /// Add a chain even listener to the mock node
    pub fn with_chain_event_listener(self) -> Self {
        let config = &self.config;
        let darkpool_client =
            self.darkpool_client.clone().expect("Darkpool client not initialized");
        let global_state = self.state.clone().expect("State not initialized");
        let handshake_manager_job_queue = self.handshake_queue.0.clone();
        let cancel_channel = mock_cancel();

        let conf = OnChainEventListenerConfig {
            websocket_addr: config.eth_websocket_addr.clone(),
            darkpool_client,
            global_state,
            handshake_manager_job_queue,
            cancel_channel,
            event_queue: self.event_queue.0.clone(),
        };

        let mut listener = run_fut(OnChainEventListener::new(conf))
            .expect("Failed to create chain event listener");
        listener.start().expect("Failed to start chain event listener");

        self
    }

    /// Add an API server to the mock node
    pub fn with_api_server(self) -> Self {
        let config = &self.config;
        let darkpool_client =
            self.darkpool_client.clone().expect("Darkpool client not initialized");
        let network_sender = self.network_queue.0.clone();
        let state = self.state.clone().expect("State not initialized");
        let system_bus = self.bus.clone();
        let price_reporter_work_queue = self.price_queue.0.clone();
        let proof_generation_work_queue = self.proof_queue.0.clone();
        let handshake_manager_work_queue = self.handshake_queue.0.clone();
        let cancel_channel = mock_cancel();

        let conf = ApiServerConfig {
            http_port: config.http_port,
            websocket_port: config.websocket_port,
            admin_api_key: config.admin_api_key,
            min_transfer_amount: config.min_transfer_amount,
            min_order_size: config.min_fill_size_decimal_adjusted(),
            chain: config.chain_id,
            compliance_service_url: config.compliance_service_url.clone(),
            wallet_task_rate_limit: config.wallet_task_rate_limit,
            darkpool_client,
            network_sender,
            state,
            system_bus,
            price_reporter_work_queue,
            proof_generation_work_queue,
            handshake_manager_work_queue,
            cancel_channel,
        };

        let mut server = run_fut(ApiServer::new(conf)).expect("Failed to create API server");
        server.start().expect("Failed to start API server");

        // Forget the server to avoid dropping it and its runtime
        mem::forget(server);
        self
    }

    /// Add a proof generation module to the mock node
    pub fn with_proof_generation(mut self) -> Self {
        let job_queue = self.proof_queue.1.take().unwrap();
        let cancel_channel = mock_cancel();
        let conf = ProofManagerConfig { job_queue, cancel_channel };

        let mut manager = run_fut(ProofManager::new(conf)).expect("Failed to create proof manager");
        manager.start().expect("Failed to start proof manager");

        self
    }

    /// Add a mock proof generation module to the mock node
    pub fn with_mock_proof_generation(mut self, skip_constraints: bool) -> Self {
        let job_queue = self.proof_queue.1.take().unwrap();
        MockProofManager::start(job_queue, skip_constraints);

        self
    }
}

// -----------
// | Helpers |
// -----------

/// Clear all files and directories within a directory, keeping the directory
/// itself
async fn clear_dir_contents(path: &str) -> Result<()> {
    // If the directory doesn't exist, do nothing
    if !std::path::Path::new(path).exists() {
        return Ok(());
    }

    let mut entries = tokio::fs::read_dir(path).await?;
    while let Some(entry) = entries.next_entry().await? {
        let entry_path = entry.path();
        if entry_path.is_dir() {
            tokio::fs::remove_dir_all(entry_path).await?;
        } else {
            tokio::fs::remove_file(entry_path).await?;
        }
    }

    Ok(())
}
