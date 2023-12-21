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
use helpers::{fund_wallet, increase_erc20_allowance, new_mock_task_driver, FUNDING_AMOUNT};
use job_types::proof_manager::ProofManagerJob;
use proof_manager::mock::MockProofManager;
use state::mock::StateMockBuilder;
use state::RelayerState;
use task_driver::driver::TaskDriver;
use test_helpers::{
    arbitrum::{DEFAULT_DEVNET_HOSTPORT, DEFAULT_DEVNET_PKEY},
    integration_test_main,
    types::TestVerbosity,
};
use tokio::sync::mpsc::{
    unbounded_channel, UnboundedReceiver as TokioReceiver, UnboundedSender as TokioSender,
};
use util::{
    arbitrum::{
        parse_addr_from_deployments_file, DARKPOOL_PROXY_CONTRACT_KEY, DUMMY_ERC20_CONTRACT_KEY,
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
    /// It is assumed that the dummy erc20 has a `mint` method that allows the
    /// test to fund its address
    #[arg(long)]
    erc20_addr: Option<String>,
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
    #[arg(long, short, default_value = "default")]
    verbosity: TestVerbosity,
}

/// The arguments provided to every integration test
#[derive(Clone)]
struct IntegrationTestArgs {
    /// The address of the darkpool deployed on the Arbitrum devnet
    darkpool_addr: String,
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

        let args = Self {
            darkpool_addr: get_darkpool_addr(&test_args),
            erc20_addr: get_erc20_addr(&test_args),
            arbitrum_client: setup_arbitrum_client_mock(test_args),
            network_sender,
            _network_receiver: Arc::new(network_receiver),
            proof_job_queue,
            global_state: setup_global_state_mock(),
            driver: new_mock_task_driver(),
        };

        // Fund the wallet with WETH and the dummy ERC20 token
        block_on_result(fund_wallet(&args)).unwrap();
        block_on_result(increase_erc20_allowance(FUNDING_AMOUNT, &args.erc20_addr, &args)).unwrap();
        args
    }
}

/// Create a global state mock for the `task-driver` integration tests
fn setup_global_state_mock() -> RelayerState {
    StateMockBuilder::default().disable_fee_validation().build()
}

/// Setup a mock `ArbitrumClient` for the integration tests
fn setup_arbitrum_client_mock(test_args: CliArgs) -> ArbitrumClient {
    // Build a client that references the darkpool
    block_on_result(ArbitrumClient::new(ArbitrumClientConfig {
        chain: Chain::Devnet,
        darkpool_addr: get_darkpool_addr(&test_args),
        arb_priv_key: test_args.arbitrum_pkey,
        rpc_url: test_args.devnet_url,
    }))
    .unwrap()
}

/// Get the address of the darkpool contract
fn get_darkpool_addr(test_args: &CliArgs) -> String {
    assert!(
        test_args.darkpool_addr.is_some() || test_args.deployments_path.is_some(),
        "Must provide either a darkpool address or a deployments file"
    );

    get_addr_maybe_from_file(
        test_args.darkpool_addr.clone(),
        DARKPOOL_PROXY_CONTRACT_KEY,
        test_args.deployments_path.as_deref().unwrap_or("/deployments.json"),
    )
}

/// Get the address of the erc20 contract
fn get_erc20_addr(test_args: &CliArgs) -> String {
    assert!(
        test_args.erc20_addr.is_some() || test_args.deployments_path.is_some(),
        "Must provide either an erc20 address or a deployments file"
    );

    get_addr_maybe_from_file(
        test_args.erc20_addr.clone(),
        DUMMY_ERC20_CONTRACT_KEY,
        test_args.deployments_path.as_deref().unwrap_or("/deployments.json"),
    )
}

/// Get an address either from the command line or by falling back to the given
/// key in the deployments file
fn get_addr_maybe_from_file(
    maybe_addr: Option<String>,
    json_key: &str,
    deployments_file: &str,
) -> String {
    if let Some(addr) = maybe_addr {
        addr
    } else {
        parse_addr_from_deployments_file(deployments_file, json_key).unwrap()
    }
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
