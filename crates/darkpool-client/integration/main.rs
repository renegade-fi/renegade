//! Defines integration tests for the Arbitrum client.
//!
//! The tests explicitly assume that the contracts have already been deployed
//! before they run. Additionally, the tests assume that the contracts have
//! proof and ECDSA verification disabled, as those are not the focus of this
//! test suite.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]

mod contract_interaction;
mod event_indexing;
mod helpers;

use std::{str::FromStr, time::Duration};

use ::constants::Scalar;
use alloy::signers::local::PrivateKeySigner;
use circuit_types::SizedWalletShare;
use clap::Parser;
use darkpool_client::{DarkpoolClient, client::DarkpoolClientConfig, constants::Chain};
use test_helpers::{
    arbitrum::{DEFAULT_DEVNET_HOSTPORT, DEFAULT_DEVNET_PKEY},
    integration_test_main,
    types::TestVerbosity,
};
use util::{
    on_chain::{DARKPOOL_PROXY_CONTRACT_KEY, parse_addr_from_deployments_file},
    telemetry::LevelFilter,
};

/// The arguments used to run the integration tests
#[derive(Debug, Clone, Parser)]
#[command(author, version, about, long_about=None)]
struct CliArgs {
    /// The private key to use for signing transactions in the integration test
    ///
    /// Defaults to the private key that the Nitro devnet is pre-seeded with
    #[arg(short = 'p', long, default_value = DEFAULT_DEVNET_PKEY)]
    private_key: String,

    /// The location of a `deployments.json` file that contains the addresses of
    /// the deployed contracts
    #[arg(short, long)]
    deployments_path: String,

    // TODO: Add a flag for the contract artifacts to allow for building/deploying
    // during test setup
    /// The url of the RPC endpoint to use for the integration test
    #[arg(long, default_value = DEFAULT_DEVNET_HOSTPORT)]
    rpc_url: String,

    /// The test to run
    #[arg(short, long, value_parser)]
    test: Option<String>,

    /// The verbosity level of the test harness
    #[arg(long, default_value = "default")]
    verbosity: TestVerbosity,
}

/// The arguments provided to every integration test
#[derive(Clone)]
struct IntegrationTestArgs {
    /// The darkpool client that resolves to a locally running devnet node
    client: DarkpoolClient,
}

/// The set of pre-allocated state elements in the contract
///
/// We insert three wallets into the state to test against, this gives two
/// wallets in each other's first-level Merkle authentication paths, and one
/// with a default value in its first-level Merkle authentication path
#[derive(Clone)]
pub struct PreAllocatedState {
    /// The commitment inserted at index 0 in the Merkle tree when integration
    /// tests begin
    pub index0_commitment: Scalar,
    /// The commitment inserted at index 1 in the Merkle tree when integration
    /// tests begin
    pub index1_commitment: Scalar,
    /// The commitment inserted at index 2 in the Merkle tree when integration
    /// tests begin
    pub index2_commitment: Scalar,
    /// The public wallet shares of the first wallet added to the tree
    pub index0_public_wallet_shares: SizedWalletShare,
    /// The public wallet shares of the second wallet added to the tree
    pub index1_public_wallet_shares: SizedWalletShare,
    /// The public wallet shares of the third wallet added to the tree
    pub index2_public_wallet_shares: SizedWalletShare,
}

impl From<CliArgs> for IntegrationTestArgs {
    fn from(test_args: CliArgs) -> Self {
        // Pull the contract address either from the CLI or a shared volume at the CLI
        // specified path

        let darkpool_addr = parse_addr_from_deployments_file(
            &test_args.deployments_path,
            DARKPOOL_PROXY_CONTRACT_KEY,
        )
        .unwrap();

        // Build a client that references the darkpool
        // We block on the client creation so that we can match the (synchronous)
        // function signature of `From`, which is assumed to be implemented in
        // the integration test harness
        let private_key = PrivateKeySigner::from_str(&test_args.private_key).unwrap();
        let client = DarkpoolClient::new(DarkpoolClientConfig {
            chain: Chain::Devnet,
            darkpool_addr,
            private_key,
            rpc_url: test_args.rpc_url,
            block_polling_interval: Duration::from_millis(100),
        })
        .unwrap();

        Self { client }
    }
}

/// Setup code for the integration tests
fn setup_integration_tests(test_args: &CliArgs) {
    // Configure logging
    if matches!(test_args.verbosity, TestVerbosity::Full) {
        util::telemetry::setup_system_logger(LevelFilter::INFO);
    }
}

integration_test_main!(CliArgs, IntegrationTestArgs, setup_integration_tests);
