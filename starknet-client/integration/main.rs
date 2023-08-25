//! Defines integration tests for
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

mod chain_state;
mod contract_interaction;
mod helpers;

use circuit_types::SizedWalletShare;
use clap::{ArgGroup, Parser};
use common::types::chain_id::ChainId;
use eyre::Result;
use mpc_stark::algebra::scalar::Scalar;
use starknet_client::client::{StarknetClient, StarknetClientConfig};
use test_helpers::{contracts::parse_addr_from_deployments_file, integration_test_main};
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
///
/// We insert three wallets into the state to test against, this gives two wallets in each
/// other's first-level Merkle authentication paths, and one with a default value in its
/// first-level Merkle authentication path
#[derive(Clone)]
struct PreAllocatedState {
    /// The commitment inserted at index 0 in the Merkle tree when integration tests begin
    index0_commitment: Scalar,
    /// The commitment inserted at index 1 in the Merkle tree when integration tests begin
    index1_commitment: Scalar,
    /// The commitment inserted at index 2 in the Merkle tree when integration tests begin
    index2_commitment: Scalar,
    /// The public wallet shares of the first wallet added to the tree
    index0_public_wallet_shares: SizedWalletShare,
    /// The public wallet shares of the second wallet added to the tree
    index1_public_wallet_shares: SizedWalletShare,
    /// The public wallet shares of the third wallet added to the tree
    index2_public_wallet_shares: SizedWalletShare,
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
    let (index0_commitment, index0_shares) = block_on_result(deploy_new_wallet(client))?;
    let (index1_commitment, index1_shares) = block_on_result(deploy_new_wallet(client))?;
    let (index2_commitment, index2_shares) = block_on_result(deploy_new_wallet(client))?;

    Ok(PreAllocatedState {
        index0_commitment,
        index1_commitment,
        index2_commitment,
        index0_public_wallet_shares: index0_shares,
        index1_public_wallet_shares: index1_shares,
        index2_public_wallet_shares: index2_shares,
    })
}

/// Setup code for the integration tests
fn setup_integration_tests(_test_args: &CliArgs) {
    // Configure logging
    util::logging::setup_system_logger(LevelFilter::Info);
}

integration_test_main!(CliArgs, IntegrationTestArgs, setup_integration_tests);
