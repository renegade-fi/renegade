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
use gossip_api::gossip::GossipOutbound;
use helpers::new_mock_task_driver;
use job_types::proof_manager::ProofManagerJob;
use proof_manager::mock::MockProofManager;
use state::mock::StateMockBuilder;
use state::RelayerState;
use task_driver::driver::TaskDriver;
use test_helpers::{
    arbitrum::{DEFAULT_DEVNET_HOSTPORT, DEFAULT_DEVNET_PKEY},
    integration_test_main,
};
use tokio::sync::mpsc::{
    unbounded_channel, UnboundedReceiver as TokioReceiver, UnboundedSender as TokioSender,
};
use util::{
    arbitrum::{parse_addr_from_deployments_file, DARKPOOL_PROXY_CONTRACT_KEY},
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
    /// The private key to use for the Starknet account during testing
    ///
    /// Defaults to the first pre-deployed account on the `nitro-testnode`
    #[arg(
        short = 'p',
        long,
        default_value = DEFAULT_DEVNET_PKEY
    )]
    arbitrum_pkey: String,
    /// The address of the darkpool deployed on Starknet at the time the test is
    /// started
    ///
    /// If not provided, the test will deploy a new darkpool contract
    #[arg(long)]
    darkpool_addr: Option<String>,
    /// The address of a dummy ERC-20 token deployed on the devnet node
    ///
    /// It is assumed that the given account address has a balance of this token
    /// on the devnet node. This is generally true for default values; i.e.
    /// pre-deployed accounts with the default $ETH ERC-20 token
    ///
    /// Defaults to the ETH base token address with the same address as on
    /// Goerli
    #[arg(long, default_value = "0x0")]
    erc20_addr: String,
    /// The location of a `deployments.json` file that contains the addresses of
    /// the deployed contracts
    #[arg(long)]
    deployments_path: Option<String>,
    /// The location of the contract compilation artifacts as an absolute path
    #[arg(long, default_value = "/artifacts")]
    cairo_artifacts_path: String,
    /// The url the devnet node api server
    #[arg(long, default_value = DEFAULT_DEVNET_HOSTPORT)]
    devnet_url: String,
    /// The test to run
    #[arg(short, long, value_parser)]
    test: Option<String>,
    /// The verbosity level of the test harness
    #[arg(long, short)]
    verbose: bool,
}

/// The arguments provided to every integration test
#[derive(Clone)]
struct IntegrationTestArgs {
    /// The address of a pre-deployed ERC20 for testing
    erc20_addr: String,
    /// The arbitrum client that resolves to a locally running devnet node
    arbitrum_client: ArbitrumClient,
    /// A sender to the network manager's work queue
    network_sender: TokioSender<GossipOutbound>,
    /// A receiver for the network manager's work queue
    ///
    /// Held here to avoid closing the channel on `Drop`
    _network_receiver: Arc<TokioReceiver<GossipOutbound>>,
    /// A reference to the global state of the mock proof manager
    global_state: RelayerState,
    /// The job queue for the mock proof manager
    proof_job_queue: CrossbeamSender<ProofManagerJob>,
    /// The mock task driver created for these tests
    driver: TaskDriver,
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

        Self {
            erc20_addr: test_args.erc20_addr.clone(),
            arbitrum_client: setup_arbitrum_client_mock(test_args),
            network_sender,
            _network_receiver: Arc::new(network_receiver),
            proof_job_queue,
            global_state: setup_global_state_mock(),
            driver: new_mock_task_driver(),
        }
    }
}

/// Create a global state mock for the `task-driver` integration tests
fn setup_global_state_mock() -> RelayerState {
    StateMockBuilder::default().disable_fee_validation().build()
}

/// Setup a mock `ArbitrumClient` for the integration tests
fn setup_arbitrum_client_mock(test_args: CliArgs) -> ArbitrumClient {
    assert!(
        test_args.darkpool_addr.is_some() || test_args.deployments_path.is_some(),
        "one of `darkpool_addr` or `deployments_path` must be provided"
    );

    // The darkpool address may either be specified directly, or given by a
    // deployments file in a known location
    let darkpool_addr = if let Some(addr) = test_args.darkpool_addr {
        addr
    } else {
        parse_addr_from_deployments_file(
            &test_args.deployments_path.unwrap(),
            DARKPOOL_PROXY_CONTRACT_KEY,
        )
        .unwrap()
    };

    // Build a client that references the darkpool
    block_on_result(ArbitrumClient::new(ArbitrumClientConfig {
        chain: Chain::Devnet,
        darkpool_addr,
        arb_priv_key: test_args.arbitrum_pkey,
        rpc_url: test_args.devnet_url,
    }))
    .unwrap()
}

// ----------------
// | Test Harness |
// ----------------

/// Setup code for the integration tests
fn setup_integration_tests(_test_args: &CliArgs) {
    // Configure logging
    util::logging::setup_system_logger(LevelFilter::INFO);
}

integration_test_main!(CliArgs, IntegrationTestArgs, setup_integration_tests);
