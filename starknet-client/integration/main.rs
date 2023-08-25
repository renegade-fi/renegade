//! Defines integration tests for
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

mod chain_state;
mod helpers;

use clap::{ArgGroup, Parser};
use common::types::chain_id::ChainId;
use eyre::Result;
use mpc_stark::algebra::scalar::Scalar;
use rand::thread_rng;
use starknet_client::client::{StarknetClient, StarknetClientConfig};
use test_helpers::{
    assert_true_result, contracts::parse_addr_from_deployments_file, integration_test_async,
    integration_test_main,
};
use tracing::log;
use tracing::log::LevelFilter;
use util::runtime::block_on_result;

use crate::helpers::deploy_new_wallet;

/// The hostport that the test expects a local devnet node to be running on
///
/// This assumes that the integration tests are running in a docker-compose setup
/// with a DNS alias `sequencer` pointing to a devnet node running in a sister container
const DEVNET_HOSTPORT: &str = "http://sequencer:5050";

/// The arguments used to run the integration tests
#[derive(Debug, Clone, Parser)]
#[command(author, version, about, long_about=None)]
#[clap(group = ArgGroup::new("deploy_config").required(true).multiple(false))]
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
    #[clap(long, group = "deploy_config")]
    darkpool_addr: Option<String>,
    /// The location of a `deployments.json` file that contains the addresses of the
    /// deployed contracts
    #[arg(long, group = "deploy_config")]
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
    /// The pre-allocated state elements in the contract
    pre_allocated_state: PreAllocatedState,
}

/// The set of pre-allocated state elements in the contract
#[derive(Clone)]
struct PreAllocatedState {
    /// The commitment inserted at index 0 in the Merkle tree when integration tests begin
    index0_commitment: Scalar,
    /// The nullifier inserted at index 1 in the Merkle tree when integration tests begin
    index1_commitment: Scalar,
}

impl From<CliArgs> for IntegrationTestArgs {
    fn from(test_args: CliArgs) -> Self {
        // Pull the contract address either from the CLI or a shared volume at the CLI specified path
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
            chain: ChainId::Katana,
            contract_addr: darkpool_addr,
            starknet_json_rpc_addr: format!("{}/rpc", test_args.devnet_url),
            infura_api_key: None,
            starknet_account_addresses: vec![test_args.starknet_account_addr],
            starknet_pkeys: vec![test_args.starknet_pkey],
        });

        let pre_allocated_state = setup_pre_allocated_state(&starknet_client).unwrap();
        Self {
            starknet_client,
            pre_allocated_state,
        }
    }
}

/// Sets up pre-allocated state used by the integration tests
fn setup_pre_allocated_state(client: &StarknetClient) -> Result<PreAllocatedState> {
    // Insert two new wallets into the contract
    let index0_commitment = block_on_result(deploy_new_wallet(client))?;
    let index1_commitment = block_on_result(deploy_new_wallet(client))?;

    log::info!("index 0 commitment: {index0_commitment}");
    log::info!("index 1 commitment: {index1_commitment}");

    Ok(PreAllocatedState {
        index0_commitment,
        index1_commitment,
    })
}

/// Setup code for the integration tests
fn setup_integration_tests(_test_args: &CliArgs) {
    // Configure logging
    util::logging::setup_system_logger(LevelFilter::Info);
}

/// A dummy test that always passes
///
/// TODO: Delete this
async fn test_dummy(args: IntegrationTestArgs) -> Result<()> {
    // Test that a random nullifier is not marked as used by the contract
    let client = &args.starknet_client;

    let mut rng = thread_rng();
    let random_nullifier = Scalar::random(&mut rng);

    let unused = client.check_nullifier_unused(random_nullifier).await?;
    assert_true_result!(unused)
}

integration_test_async!(test_dummy);

integration_test_main!(CliArgs, IntegrationTestArgs, setup_integration_tests);
