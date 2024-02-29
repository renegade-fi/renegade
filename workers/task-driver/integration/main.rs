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

use std::sync::Arc;

use arbitrum_client::{
    client::{ArbitrumClient, ArbitrumClientConfig},
    constants::Chain,
};
use clap::Parser;
use crossbeam::channel::{unbounded, Sender as CrossbeamSender};
use helpers::new_mock_task_driver;
use job_types::{
    network_manager::NetworkManagerReceiver,
    proof_manager::ProofManagerJob,
    task_driver::{new_task_driver_queue, TaskDriverQueue},
};
use proof_manager::mock::MockProofManager;
use state::{test_helpers::mock_state_with_task_queue, State};
use test_helpers::{
    arbitrum::{DEFAULT_DEVNET_HOSTPORT, DEFAULT_DEVNET_PKEY},
    integration_test_main,
    types::TestVerbosity,
};
use tokio::sync::mpsc::unbounded_channel;
use util::{
    arbitrum::{
        parse_addr_from_deployments_file, DARKPOOL_PROXY_CONTRACT_KEY, DUMMY_ERC20_0_CONTRACT_KEY,
        DUMMY_ERC20_1_CONTRACT_KEY, PERMIT2_CONTRACT_KEY,
    },
    logging::LevelFilter,
    runtime::block_on_result,
};

// -------
// | CLI |
// -------

/// The arguments used to run the integration tests
#[derive(Debug, Clone, Parser)]
#[command(author, version, about, long_about=None)]
struct CliArgs {
    /// The private key to use for the Arbitrum account during testing
    ///
    /// Defaults to the first pre-deployed account on the `nitro-testnode`
    #[arg(
        short = 'p',
        long,
        default_value = DEFAULT_DEVNET_PKEY
    )]
    arbitrum_pkey: String,
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
    /// The arbitrum client that resolves to a locally running devnet node
    arbitrum_client: ArbitrumClient,
    /// A receiver for the network manager's work queue
    ///
    /// Held here to avoid closing the channel on `Drop`
    _network_receiver: Arc<NetworkManagerReceiver>,
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
        let (network_sender, network_receiver) = unbounded_channel();

        // Create a mock proof generation module
        let (proof_job_queue, job_receiver) = unbounded();
        MockProofManager::start(job_receiver);

        // Create a mock arbitrum client
        let arbitrum_client = setup_arbitrum_client_mock(&test_args);

        // Create a mock state instance and a task driver
        let (task_queue, task_recv) = new_task_driver_queue();
        let state = setup_global_state_mock(task_queue.clone());

        // Start a task driver
        new_mock_task_driver(
            task_recv,
            arbitrum_client.clone(),
            network_sender,
            proof_job_queue.clone(),
            state.clone(),
        );

        let erc20_addr0 = parse_addr_from_deployments_file(
            &test_args.deployments_path,
            DUMMY_ERC20_0_CONTRACT_KEY,
        )
        .unwrap();
        let erc20_addr1 = parse_addr_from_deployments_file(
            &test_args.deployments_path,
            DUMMY_ERC20_1_CONTRACT_KEY,
        )
        .unwrap();
        let permit2_addr =
            parse_addr_from_deployments_file(&test_args.deployments_path, PERMIT2_CONTRACT_KEY)
                .unwrap();

        Self {
            erc20_addr0,
            erc20_addr1,
            permit2_addr,
            arbitrum_client,
            _network_receiver: Arc::new(network_receiver),
            proof_job_queue,
            state,
            task_queue,
        }
    }
}

/// Create a global state mock for the `task-driver` integration tests
fn setup_global_state_mock(task_queue: TaskDriverQueue) -> State {
    mock_state_with_task_queue(task_queue)
}

/// Setup a mock `ArbitrumClient` for the integration tests
fn setup_arbitrum_client_mock(test_args: &CliArgs) -> ArbitrumClient {
    let darkpool_addr =
        parse_addr_from_deployments_file(&test_args.deployments_path, DARKPOOL_PROXY_CONTRACT_KEY)
            .unwrap();

    // Build a client that references the darkpool
    block_on_result(ArbitrumClient::new(ArbitrumClientConfig {
        chain: Chain::Devnet,
        darkpool_addr,
        arb_priv_key: test_args.arbitrum_pkey.clone(),
        rpc_url: test_args.devnet_url.clone(),
    }))
    .unwrap()
}

// ----------------
// | Test Harness |
// ----------------

/// Setup code for the integration tests
fn setup_integration_tests(test_args: &CliArgs) {
    // Configure logging
    if matches!(test_args.verbosity, TestVerbosity::Full) {
        util::logging::setup_system_logger(LevelFilter::INFO);
    }
}

integration_test_main!(CliArgs, IntegrationTestArgs, setup_integration_tests);
