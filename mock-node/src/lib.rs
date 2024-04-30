//! Defines mock node methods for integration testing

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use std::{collections::HashSet, mem};

use api_server::worker::{ApiServer, ApiServerConfig};
use arbitrum_client::client::{ArbitrumClient, ArbitrumClientConfig};
use chain_events::listener::{OnChainEventListener, OnChainEventListenerConfig};
use common::{
    default_wrapper::{default_option, DefaultOption},
    types::Price,
    worker::Worker,
};
use config::RelayerConfig;
use ed25519_dalek::Keypair;
use external_api::bus_message::SystemBusMessage;
use gossip_server::{server::GossipServer, worker::GossipServerConfig};
use handshake_manager::{manager::HandshakeManager, worker::HandshakeManagerConfig};
use job_types::{
    gossip_server::{
        new_gossip_server_queue, GossipServerJob, GossipServerQueue, GossipServerReceiver,
    },
    handshake_manager::{
        new_handshake_manager_queue, HandshakeExecutionJob, HandshakeManagerQueue,
        HandshakeManagerReceiver,
    },
    network_manager::{
        new_network_manager_queue, NetworkManagerJob, NetworkManagerQueue, NetworkManagerReceiver,
    },
    price_reporter::{
        new_price_reporter_queue, PriceReporterJob, PriceReporterQueue, PriceReporterReceiver,
    },
    proof_manager::{
        new_proof_manager_queue, ProofManagerJob, ProofManagerQueue, ProofManagerReceiver,
    },
    task_driver::{new_task_driver_queue, TaskDriverJob, TaskDriverQueue, TaskDriverReceiver},
};
use libp2p::Multiaddr;
use network_manager::{manager::NetworkManager, worker::NetworkManagerConfig};
use price_reporter::{
    manager::PriceReporter,
    mock::{setup_mock_token_remap, MockPriceReporter},
    worker::{ExchangeConnectionsConfig, PriceReporterConfig},
};
use proof_manager::{
    mock::MockProofManager, proof_manager::ProofManager, worker::ProofManagerConfig,
};
use reqwest::{blocking::Client, Method};
use serde::{de::DeserializeOwned, Serialize};
use state::{
    replication::{
        network::traits::{new_raft_message_queue, RaftMessageQueue, RaftMessageReceiver},
        raft_node::{
            new_raft_proposal_queue, ProposalQueue, ProposalReceiver, ReplicationNodeConfig,
        },
        worker::ReplicationNodeWorker,
    },
    State,
};
use system_bus::SystemBus;
use task_driver::worker::{TaskDriver, TaskDriverConfig};
use test_helpers::mocks::mock_cancel;
use tokio::runtime::Runtime as TokioRuntime;

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
    /// The arbitrum client
    arbitrum_client: Option<ArbitrumClient>,
    /// The system bus
    bus: SystemBus<SystemBusMessage>,
    /// The global state (if initialized)
    state: Option<State>,

    // --- Worker Queues --- //
    /// The network manager's queue
    network_queue: (NetworkManagerQueue, DefaultOption<NetworkManagerReceiver>),
    /// The raft message queue
    raft_queue: (RaftMessageQueue, DefaultOption<RaftMessageReceiver>),
    /// The raft proposal queue
    proposal_queue: (ProposalQueue, DefaultOption<ProposalReceiver>),
    /// The gossip message queue
    gossip_queue: (GossipServerQueue, DefaultOption<GossipServerReceiver>),
    /// The handshake manager's queue
    handshake_queue: (HandshakeManagerQueue, DefaultOption<HandshakeManagerReceiver>),
    /// The price reporter's queue
    price_queue: (PriceReporterQueue, DefaultOption<PriceReporterReceiver>),
    /// The proof generation queue
    proof_queue: (ProofManagerQueue, DefaultOption<ProofManagerReceiver>),
    /// The task manager queue
    task_queue: (TaskDriverQueue, DefaultOption<TaskDriverReceiver>),
}

/// All methods use a builder pattern to allow chained construction
impl MockNodeController {
    /// Constructor
    pub fn new(config: RelayerConfig) -> Self {
        let bus = SystemBus::new();
        let (network_sender, network_recv) = new_network_manager_queue();
        let (raft_sender, raft_recv) = new_raft_message_queue();
        let (proposal_sender, proposal_receiver) = new_raft_proposal_queue();
        let (gossip_sender, gossip_recv) = new_gossip_server_queue();
        let (handshake_send, handshake_recv) = new_handshake_manager_queue();
        let (price_sender, price_recv) = new_price_reporter_queue();
        let (proof_gen_sender, proof_gen_recv) = new_proof_manager_queue();
        let (task_sender, task_recv) = new_task_driver_queue();

        Self {
            config,
            local_addr: Multiaddr::empty(),
            arbitrum_client: None,
            bus,
            state: None,
            network_queue: (network_sender, default_option(network_recv)),
            raft_queue: (raft_sender, default_option(raft_recv)),
            proposal_queue: (proposal_sender, default_option(proposal_receiver)),
            gossip_queue: (gossip_sender, default_option(gossip_recv)),
            handshake_queue: (handshake_send, default_option(handshake_recv)),
            price_queue: (price_sender, default_option(price_recv)),
            proof_queue: (proof_gen_sender, default_option(proof_gen_recv)),
            task_queue: (task_sender, default_option(task_recv)),
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

    /// Get a copy of the global state
    ///
    /// Panics if the state is not initialized
    pub fn state(&self) -> State {
        self.state.clone().expect("State not initialized")
    }

    /// Get a handle to the arbitrum client
    pub fn arbitrum_client(&self) -> ArbitrumClient {
        self.arbitrum_client.clone().expect("Arbitrum client not initialized")
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
    pub fn send_api_req<B: Serialize, R: DeserializeOwned>(
        &self,
        route: &str,
        method: Method,
        body: B,
    ) -> Result<R, String> {
        let client = Client::new();
        let url = format!("http://localhost:{}{}", self.config.http_port, route);

        let resp = match method {
            Method::GET => client.get(url).send().map_err(|e| e.to_string()),
            Method::POST => client.post(url).json(&body).send().map_err(|e| e.to_string()),
            _ => Err("Unsupported method".to_string()),
        }
        .map_err(|e| e.to_string())?;

        if resp.status().is_success() {
            resp.json().map_err(|e| e.to_string())
        } else {
            Err(format!("Request failed with status: {}", resp.status()))
        }
    }

    /// Send a job to the task driver
    pub fn send_task_job(&self, job: TaskDriverJob) -> Result<(), String> {
        self.task_queue.0.send(job).map_err(|e| e.to_string())
    }

    /// Send a job to the network manager
    pub fn send_network_job(&self, job: NetworkManagerJob) -> Result<(), String> {
        self.network_queue.0.send(job).map_err(|e| e.to_string())
    }

    /// Send a job to the gossip server
    pub fn send_gossip_job(&self, job: GossipServerJob) -> Result<(), String> {
        self.gossip_queue.0.send(job).map_err(|e| e.to_string())
    }

    /// Send a job to the handshake manager
    pub fn send_handshake_job(&self, job: HandshakeExecutionJob) -> Result<(), String> {
        self.handshake_queue.0.send(job).map_err(|e| e.to_string())
    }

    /// Send a job to the price reporter
    pub fn send_price_reporter_job(&self, job: PriceReporterJob) -> Result<(), String> {
        self.price_queue.0.send(job).map_err(|e| e.to_string())
    }

    /// Send a job to the proof manager
    pub fn send_proof_job(&self, job: ProofManagerJob) -> Result<(), String> {
        self.proof_queue.0.send(job).map_err(|e| e.to_string())
    }

    // ------------
    // | Builders |
    // ------------

    /// Add an arbitrum client to the mock node
    pub fn with_arbitrum_client(mut self) -> Self {
        let conf = ArbitrumClientConfig {
            darkpool_addr: self.config.contract_address.clone(),
            chain: self.config.chain_id,
            rpc_url: self.config.rpc_url.clone().unwrap(),
            arb_priv_key: self.config.arbitrum_private_key.clone(),
        };

        // Expects to be running in a Tokio runtime
        let rt = TokioRuntime::new().expect("Failed to create tokio runtime");
        let client =
            rt.block_on(ArbitrumClient::new(conf)).expect("Failed to create arbitrum client");
        self.arbitrum_client = Some(client);

        self
    }

    /// Add a global state instance to the mock node
    pub fn with_state(mut self) -> Self {
        // Create a global state instance
        let network_queue = self.network_queue.0.clone();
        let raft_receiver = self.raft_queue.1.take().unwrap();
        let proposal_sender = self.proposal_queue.0.clone();
        let proposal_receiver = self.proposal_queue.1.take().unwrap();
        let task_sender = self.task_queue.0.clone();
        let handshake_queue = self.handshake_queue.0.clone();
        let bus = self.bus.clone();
        let cancel_channel = mock_cancel();

        let state = State::new(&self.config, proposal_sender, bus.clone())
            .expect("Failed to create state instance");

        // Start the raft node
        let mut replication_config = ReplicationNodeConfig::new(
            self.config.clone(),
            proposal_receiver,
            task_sender,
            handshake_queue,
            bus,
            cancel_channel,
        );
        state.fill_replication_config(&mut replication_config, network_queue, raft_receiver);

        let mut raft_worker = ReplicationNodeWorker::new(replication_config)
            .expect("failed to build Raft replication node");
        raft_worker.start().expect("failed to start Raft replication node");

        self.state = Some(state);
        self
    }

    /// Add a task driver to the mock node
    pub fn with_task_driver(mut self) -> Self {
        let task_queue = self.task_queue.1.take().unwrap();
        let arbitrum_client =
            self.arbitrum_client.clone().expect("Arbitrum client not initialized");
        let network_queue = self.network_queue.0.clone();
        let proof_queue = self.proof_queue.0.clone();
        let bus = self.bus.clone();
        let state = self.state.clone().expect("State not initialized");

        let conf = TaskDriverConfig::new(
            task_queue,
            arbitrum_client,
            network_queue,
            proof_queue,
            bus,
            state,
        );
        let mut driver = TaskDriver::new(conf).expect("Failed to create task driver");
        driver.start().expect("Failed to start task driver");

        self
    }

    /// Add a network manager to the mock node
    pub fn with_network_manager(mut self) -> Self {
        let config = &self.config;
        let network_recv = self.network_queue.1.take().unwrap();
        let raft_sender = self.raft_queue.0.clone();
        let gossip_sender = self.gossip_queue.0.clone();
        let handshake_send = self.handshake_queue.0.clone();
        let cancel_channel = mock_cancel();

        let conf = NetworkManagerConfig {
            port: config.p2p_port,
            bind_addr: config.bind_addr,
            known_public_addr: config.public_ip,
            allow_local: config.allow_local,
            cluster_id: config.cluster_id.clone(),
            cluster_keypair: Some(self.clone_cluster_key()),
            send_channel: Some(network_recv),
            raft_queue: raft_sender,
            gossip_work_queue: gossip_sender,
            handshake_work_queue: handshake_send,
            system_bus: self.bus.clone(),
            global_state: self.state.clone().expect("State not initialized"),
            cancel_channel,
        };
        let mut manager = NetworkManager::new(conf).expect("Failed to create network manager");
        manager.start().expect("Failed to start network manager");

        // Set the local addr after the manager binds to it
        self.local_addr = manager.local_addr;

        self
    }

    /// Add a gossip server to the mock node
    pub fn with_gossip_server(mut self) -> Self {
        let config = &self.config;
        let state = self.state.clone().expect("State not initialized");
        let local_peer_id = state.get_peer_id().expect("Failed to get peer id");
        let arbitrum_client =
            self.arbitrum_client.clone().expect("Arbitrum client not initialized");

        let job_sender = self.gossip_queue.0.clone();
        let job_receiver = self.gossip_queue.1.take().unwrap();
        let network_sender = self.network_queue.0.clone();

        let conf = GossipServerConfig {
            local_peer_id,
            local_addr: self.local_addr.clone(),
            cluster_id: config.cluster_id.clone(),
            bootstrap_servers: config.bootstrap_servers.clone(),
            arbitrum_client,
            global_state: state,
            job_sender,
            job_receiver: default_option(job_receiver),
            network_sender,
            cancel_channel: mock_cancel(),
        };
        let mut server = GossipServer::new(conf).expect("Failed to create gossip server");
        server.start().expect("Failed to start gossip server");

        self
    }

    /// Add a handshake manager to the mock node
    pub fn with_handshake_manager(mut self) -> Self {
        let global_state = self.state.clone().expect("State not initialized");
        let network_channel = self.network_queue.0.clone();
        let price_reporter_job_queue = self.price_queue.0.clone();
        let job_sender = self.handshake_queue.0.clone();
        let job_receiver = self.handshake_queue.1.take().unwrap();
        let cancel_channel = mock_cancel();
        let system_bus = self.bus.clone();
        let task_queue = self.task_queue.0.clone();

        let conf = HandshakeManagerConfig {
            mutual_exclusion_list: HashSet::new(),
            global_state,
            network_channel,
            price_reporter_job_queue,
            job_sender,
            job_receiver: Some(job_receiver),
            task_queue,
            system_bus,
            cancel_channel,
        };
        let mut manager = HandshakeManager::new(conf).expect("Failed to create handshake manager");
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
                coinbase_api_key: config.coinbase_api_key.clone(),
                coinbase_api_secret: config.coinbase_api_secret.clone(),
                eth_websocket_addr: config.eth_websocket_addr.clone(),
            },
            price_reporter_url: config.price_reporter_url.clone(),
            disabled: config.disable_price_reporter,
            disabled_exchanges: config.disabled_exchanges.clone(),
            job_receiver: default_option(job_receiver),
            system_bus,
            cancel_channel,
        };
        let mut reporter = PriceReporter::new(conf).expect("Failed to create price reporter");
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
        let arbitrum_client =
            self.arbitrum_client.clone().expect("Arbitrum client not initialized");
        let global_state = self.state.clone().expect("State not initialized");
        let handshake_manager_job_queue = self.handshake_queue.0.clone();
        let proof_generation_work_queue = self.proof_queue.0.clone();
        let network_sender = self.network_queue.0.clone();
        let cancel_channel = mock_cancel();

        let conf = OnChainEventListenerConfig {
            max_root_staleness: config.max_merkle_staleness,
            arbitrum_client,
            global_state,
            handshake_manager_job_queue,
            proof_generation_work_queue,
            network_sender,
            cancel_channel,
        };

        let mut listener =
            OnChainEventListener::new(conf).expect("Failed to create chain event listener");
        listener.start().expect("Failed to start chain event listener");

        self
    }

    /// Add an API server to the mock node
    pub fn with_api_server(self) -> Self {
        let config = &self.config;
        let network_sender = self.network_queue.0.clone();
        let global_state = self.state.clone().expect("State not initialized");
        let system_bus = self.bus.clone();
        let price_reporter_work_queue = self.price_queue.0.clone();
        let proof_generation_work_queue = self.proof_queue.0.clone();
        let cancel_channel = mock_cancel();

        let conf = ApiServerConfig {
            http_port: config.http_port,
            websocket_port: config.websocket_port,
            network_sender,
            global_state,
            system_bus,
            price_reporter_work_queue,
            proof_generation_work_queue,
            cancel_channel,
        };

        let mut server = ApiServer::new(conf).expect("Failed to create API server");
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

        let mut manager = ProofManager::new(conf).expect("Failed to create proof manager");
        manager.start().expect("Failed to start proof manager");

        self
    }

    /// Add a mock proof generation module to the mock node
    pub fn with_mock_proof_generation(mut self) -> Self {
        let job_queue = self.proof_queue.1.take().unwrap();
        MockProofManager::start(job_queue);

        self
    }
}

#[cfg(test)]
mod test {
    use api_server::http::PING_ROUTE;
    use config::RelayerConfig;
    use external_api::{http::PingResponse, EmptyRequestResponse};
    use reqwest::Method;
    use test_helpers::arbitrum::get_devnet_key;

    use crate::MockNodeController;

    /// Tests a simple constructor of the mock node
    #[test]
    fn test_ping_mock() {
        let conf = RelayerConfig {
            rpc_url: Some("http://localhost:1234".to_string()),
            arbitrum_private_key: get_devnet_key(),
            ..Default::default()
        };

        // A simple no-panic test
        let node = MockNodeController::new(conf.clone()).with_state().with_api_server();

        // Send a ping to check the health of the mock
        let _ping_resp: PingResponse =
            node.send_api_req(PING_ROUTE, Method::GET, EmptyRequestResponse {}).unwrap();
    }
}
