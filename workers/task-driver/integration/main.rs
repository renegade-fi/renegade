//! Defines integration tests for
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

mod helpers;
mod tests;

use std::{str::FromStr, sync::Arc};

use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::Address;
use circuit_types::{elgamal::DecryptionKey, fixed_point::FixedPoint};
use clap::Parser;
use crossbeam::channel::Sender as CrossbeamSender;
use darkpool_client::{client::DarkpoolClientConfig, constants::Chain, DarkpoolClient};
use helpers::new_mock_task_driver;
use job_types::{
    event_manager::{new_event_manager_queue, EventManagerReceiver},
    network_manager::{new_network_manager_queue, NetworkManagerReceiver},
    proof_manager::{new_proof_manager_queue, ProofManagerJob},
    task_driver::{new_task_driver_queue, TaskDriverQueue},
};
use proof_manager::mock::MockProofManager;
use rand::thread_rng;
use state::{
    test_helpers::{mock_relayer_config, mock_state_with_task_queue},
    State,
};
use test_helpers::{
    arbitrum::{DEFAULT_DEVNET_HOSTPORT, DEFAULT_DEVNET_PKEY},
    integration_test_main,
    types::TestVerbosity,
};
use util::{
    concurrency::runtime::block_current,
    on_chain::{
        parse_addr_from_deployments_file, parse_erc20_addr_from_deployments_file,
        DARKPOOL_PROXY_CONTRACT_KEY, DUMMY_ERC20_0_TICKER, DUMMY_ERC20_1_TICKER,
        PERMIT2_CONTRACT_KEY, PROTOCOL_FEE, PROTOCOL_PUBKEY,
    },
    telemetry::LevelFilter,
};

// -------
// | CLI |
// -------

/// The arguments used to run the integration tests
#[derive(Debug, Clone, Parser)]
#[command(author, version, about, long_about=None)]
struct CliArgs {
    /// The private key to use for the EVM account during testing
    ///
    /// Defaults to the first pre-deployed account on the `nitro-testnode`
    #[arg(
        short = 'p',
        long,
        default_value = DEFAULT_DEVNET_PKEY
    )]
    pkey: String,
    /// The location of a `deployments.json` file that contains the addresses of
    /// the deployed contracts
    #[arg(long)]
    deployments_path: String,
    /// The url the devnet node api server
    #[arg(long, default_value = DEFAULT_DEVNET_HOSTPORT)]
    devnet_url: String,
    /// The test to run
    #[arg(short, long, value_parser)]
    test: Option<String>,
    /// The verbosity level of the test harness
    #[arg(long, short, default_value = "default")]
    verbosity: TestVerbosity,
}

/// The arguments provided to every integration test
#[derive(Clone)]
struct IntegrationTestArgs {
    /// The address of the first pre-deployed ERC20 for testing
    erc20_addr0: String,
    /// The address of the second pre-deployed ERC20 for testing
    erc20_addr1: String,
    /// The address of the Permit2 contract
    permit2_addr: String,
    /// The darkpool client that resolves to a locally running devnet node
    darkpool_client: DarkpoolClient,
    /// The private key of the account used for the relayer
    pkey: PrivateKeySigner,
    /// A receiver for the network manager's work queue
    ///
    /// Held here to avoid closing the channel on `Drop`
    _network_receiver: Arc<NetworkManagerReceiver>,
    /// A receiver for the event manager's work queue
    ///
    /// Held here to avoid closing the channel on `Drop`
    _event_receiver: Arc<EventManagerReceiver>,
    /// A reference to the global state of the mock proof manager
    state: State,
    /// The job queue for the mock proof manager
    proof_job_queue: CrossbeamSender<ProofManagerJob>,
    /// The task driver queue used to enqueue tasks
    task_queue: TaskDriverQueue,
}

// -----------
// | Mocking |
// -----------

impl From<CliArgs> for IntegrationTestArgs {
    fn from(test_args: CliArgs) -> Self {
        // Create a mock network sender and receiver
        let (network_sender, network_receiver) = new_network_manager_queue();

        // Create a mock proof generation module
        let (proof_job_queue, job_receiver) = new_proof_manager_queue();
        MockProofManager::start(job_receiver);

        // Create a mock darkpool client
        let pkey = PrivateKeySigner::from_str(&test_args.pkey).unwrap();
        let darkpool_client = setup_darkpool_client_mock(&test_args);

        // Create a mock state instance and a task driver
        let (task_queue, task_recv) = new_task_driver_queue();
        let state = block_current(setup_global_state_mock(task_queue.clone()));

        // Create a mock event sender and receiver
        let (event_queue, event_receiver) = new_event_manager_queue();

        // Start a task driver
        new_mock_task_driver(
            task_recv,
            task_queue.clone(),
            darkpool_client.clone(),
            network_sender,
            proof_job_queue.clone(),
            event_queue,
            state.clone(),
        );

        let erc20_addr0 = parse_erc20_addr_from_deployments_file(
            &test_args.deployments_path,
            DUMMY_ERC20_0_TICKER,
        )
        .unwrap();
        let erc20_addr1 = parse_erc20_addr_from_deployments_file(
            &test_args.deployments_path,
            DUMMY_ERC20_1_TICKER,
        )
        .unwrap();
        let permit2_addr =
            parse_addr_from_deployments_file(&test_args.deployments_path, PERMIT2_CONTRACT_KEY)
                .unwrap();

        Self {
            erc20_addr0,
            erc20_addr1,
            permit2_addr,
            darkpool_client,
            pkey,
            _network_receiver: Arc::new(network_receiver),
            _event_receiver: Arc::new(event_receiver),
            proof_job_queue,
            state,
            task_queue,
        }
    }
}

impl IntegrationTestArgs {
    /// Get the address of the (assumed to be only) EVM account
    /// with which the relayer is configured
    pub fn wallet_address(&self) -> Address {
        self.pkey.address()
    }
}

/// Create a global state mock for the `task-driver` integration tests
async fn setup_global_state_mock(task_queue: TaskDriverQueue) -> State {
    mock_state_with_task_queue(0 /* network_delay_ms */, task_queue, &mock_relayer_config()).await
}

/// Setup a mock `DarkpoolClient` for the integration tests
fn setup_darkpool_client_mock(test_args: &CliArgs) -> DarkpoolClient {
    let private_key = PrivateKeySigner::from_str(&test_args.pkey).unwrap();
    let darkpool_addr =
        parse_addr_from_deployments_file(&test_args.deployments_path, DARKPOOL_PROXY_CONTRACT_KEY)
            .unwrap();

    // Build a client that references the darkpool
    DarkpoolClient::new(DarkpoolClientConfig {
        chain: Chain::Devnet,
        darkpool_addr,
        private_key,
        rpc_url: test_args.devnet_url.clone(),
        block_polling_interval_ms: 100,
    })
    .unwrap()
}

// ----------------
// | Test Harness |
// ----------------

/// Setup code for the integration tests
fn setup_integration_tests(test_args: &CliArgs) {
    // Set the protocol fee and pubkey
    let protocol_fee = FixedPoint::from_f64_round_down(0.0006); // 6 bps
    PROTOCOL_FEE.set(protocol_fee).expect("protocol fee already set");

    let mut rng = thread_rng();
    let protocol_key = DecryptionKey::random(&mut rng).public_key();
    PROTOCOL_PUBKEY.set(protocol_key).expect("protocol pubkey already set");

    // Configure logging
    if matches!(test_args.verbosity, TestVerbosity::Full) {
        util::telemetry::setup_system_logger(LevelFilter::INFO);
    }
}

integration_test_main!(CliArgs, IntegrationTestArgs, setup_integration_tests);
