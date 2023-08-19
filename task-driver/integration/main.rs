//! Defines integration tests for
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

mod create_new_wallet;
mod helpers;

use clap::Parser;
use common::types::chain_id::ChainId;
use crossbeam::channel::{unbounded, Sender as CrossbeamSender};
use eyre::{eyre, Result};
use helpers::new_mock_task_driver;
use job_types::proof_manager::ProofManagerJob;
use mpc_stark::algebra::scalar::Scalar;
use proof_manager::mock::MockProofManager;
use rand::thread_rng;
use starknet_client::client::{StarknetClient, StarknetClientConfig};
use state::mock::StateMockBuilder;
use state::RelayerState;
use task_driver::driver::TaskDriver;
use test_helpers::{
    contracts::parse_addr_from_deployments_file, integration_test, integration_test_main,
};
use tracing::log::LevelFilter;
use util::runtime::await_result;

/// The hostport that the test expects a local devnet node to be running on
///
/// This assumes that the integration tests are running in a docker-compose setup
/// with a DNS alias `sequencer` pointing to a devnet node running in a sister container
const DEVNET_HOSTPORT: &str = "http://sequencer:5050";

/// The arguments used to run the integration tests
#[derive(Debug, Clone, Parser)]
#[command(author, version, about, long_about=None)]
struct CliArgs {
    /// The private key to use for the Starknet account during testing
    ///
    /// Defaults to the first pre-deployed account on `starknet-devnet` when
    /// run with seed 0
    #[arg(
        short = 'p',
        long,
        default_value = "0x300001800000000300000180000000000030000000000003006001800006600"
    )]
    starknet_pkey: String,
    /// The address of the account contract to use for testing
    ///
    /// Defaults to the first pre-deployed account on `starknet-devnet` when
    /// run with seed 0
    #[arg(
        long,
        default_value = "0x3ee9e18edc71a6df30ac3aca2e0b02a198fbce19b7480a63a0d71cbd76652e0"
    )]
    starknet_account_addr: String,
    /// The address of the darkpool deployed on Starknet at the time the test is started
    ///
    /// If not provided, the test will deploy a new darkpool contract
    #[arg(long)]
    darkpool_addr: Option<String>,
    /// The location of a `deployments.json` file that contains the addresses of the
    /// deployed contracts
    #[arg(long)]
    deployments_path: Option<String>,
    /// The location of the contract compilation artifacts as an absolute path
    #[arg(long, default_value = "/artifacts")]
    cairo_artifacts_path: String,
    /// The url the devnet node api server
    #[arg(long, default_value = DEVNET_HOSTPORT)]
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
    /// The starknet client that resolves to a locally running devnet node
    starknet_client: StarknetClient,
    /// A reference to the global state of the mock proof manager
    global_state: RelayerState,
    /// The job queue for the mock proof manager
    proof_job_queue: CrossbeamSender<ProofManagerJob>,
    /// The mock task driver created for these tests
    driver: TaskDriver,
}

impl From<CliArgs> for IntegrationTestArgs {
    fn from(test_args: CliArgs) -> Self {
        // Create a mock task driver
        let driver = new_mock_task_driver();

        // Create a mock proof generation module
        let (proof_job_queue, job_receiver) = unbounded();
        MockProofManager::start(job_receiver);

        // Create a mock of the global state
        let global_state = StateMockBuilder::default().build();

        // Deploy a version of the darkpool if one is not given
        assert!(
            test_args.darkpool_addr.is_some() || test_args.deployments_path.is_some(),
            "one of `darkpool_addr` or `deployments_path` must be provided"
        );
        let darkpool_addr = if let Some(addr) = test_args.darkpool_addr {
            addr
        } else {
            parse_addr_from_deployments_file(test_args.deployments_path.unwrap()).unwrap()
        };

        // Build a client that references the darkpool
        let starknet_client = StarknetClient::new(StarknetClientConfig {
            chain: ChainId::Devnet,
            contract_addr: darkpool_addr,
            starknet_json_rpc_addr: Some(format!("{}/rpc", test_args.devnet_url)),
            sequencer_addr: Some(test_args.devnet_url),
            infura_api_key: None,
            starknet_account_addresses: vec![test_args.starknet_account_addr],
            starknet_pkeys: vec![test_args.starknet_pkey],
        });

        Self {
            starknet_client,
            proof_job_queue,
            global_state,
            driver,
        }
    }
}

/// Setup code for the integration tests
fn setup_integration_tests(_test_args: &CliArgs) {
    // Configure logging
    util::logging::setup_system_logger(LevelFilter::Info);
}

/// Dummy test
///
/// TODO: Remove this test
fn test_dummy(test_args: IntegrationTestArgs) -> Result<()> {
    let client = &test_args.starknet_client;
    let mut rng = thread_rng();
    let random_nullifier = Scalar::random(&mut rng);

    let res = await_result(client.check_nullifier_unused(random_nullifier))?;

    if res {
        Ok(())
    } else {
        Err(eyre!("nullifier already used"))
    }
}
integration_test!(test_dummy);

integration_test_main!(CliArgs, IntegrationTestArgs, setup_integration_tests);
