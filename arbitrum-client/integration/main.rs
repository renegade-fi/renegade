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
#![feature(generic_const_exprs)]

mod constants;
mod event_indexing;
mod helpers;

use ::constants::Scalar;
use arbitrum_client::{
    client::{ArbitrumClient, ArbitrumClientConfig},
    constants::Chain,
};
use circuits::zk_circuits::test_helpers::SizedWalletShare;
use clap::Parser;
use constants::{DARKPOOL_PROXY_CONTRACT_KEY, MERKLE_CONTRACT_KEY};
use eyre::Result;
use helpers::{deploy_new_wallet, parse_addr_from_deployments_file};
use test_helpers::integration_test_main;
use util::{logging::LevelFilter, runtime::block_on_result};

use crate::constants::{DEFAULT_DEVNET_HOSTPORT, DEFAULT_DEVNET_PKEY};

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
    /// The url of the Arbitrum RPC endpoint to use for the integration test
    #[arg(long, default_value = DEFAULT_DEVNET_HOSTPORT)]
    rpc_url: String,

    /// The test to run
    #[arg(short, long, value_parser)]
    test: Option<String>,

    /// The verbosity level of the test harness
    #[arg(short, long)]
    verbose: bool,
}

/// The arguments provided to every integration test
#[derive(Clone)]
struct IntegrationTestArgs {
    /// The Arbitrum client that resolves to a locally running devnet node
    client: ArbitrumClient,
    /// The pre-allocated state elements in the contract
    pre_allocated_state: PreAllocatedState,
}

/// The set of pre-allocated state elements in the contract
///
/// We insert three wallets into the state to test against, this gives two
/// wallets in each other's first-level Merkle authentication paths, and one
/// with a default value in its first-level Merkle authentication path
#[derive(Clone)]
struct PreAllocatedState {
    /// The commitment inserted at index 0 in the Merkle tree when integration
    /// tests begin
    index0_commitment: Scalar,
    /// The commitment inserted at index 1 in the Merkle tree when integration
    /// tests begin
    index1_commitment: Scalar,
    /// The commitment inserted at index 2 in the Merkle tree when integration
    /// tests begin
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
        // Pull the contract address either from the CLI or a shared volume at the CLI
        // specified path

        let darkpool_addr = parse_addr_from_deployments_file(
            &test_args.deployments_path,
            DARKPOOL_PROXY_CONTRACT_KEY,
        )
        .unwrap();
        let merkle_event_source =
            parse_addr_from_deployments_file(&test_args.deployments_path, MERKLE_CONTRACT_KEY)
                .unwrap();

        // Build a client that references the darkpool
        // We block on the client creation so that we can match the (synchronous)
        // function signature of `From`, which is assumed to be implemented in
        // the integration test harness
        let client = block_on_result(ArbitrumClient::new(ArbitrumClientConfig {
            chain: Chain::Devnet,
            darkpool_addr,
            merkle_event_source,
            arb_priv_key: test_args.private_key,
            rpc_url: test_args.rpc_url,
        }))
        .unwrap();

        let pre_allocated_state = setup_pre_allocated_state(&client).unwrap();

        Self { client, pre_allocated_state }
    }
}

/// Sets up pre-allocated state used by the integration tests
fn setup_pre_allocated_state(client: &ArbitrumClient) -> Result<PreAllocatedState> {
    // Insert three new wallets into the contract
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
    util::logging::setup_system_logger(LevelFilter::INFO);
}

integration_test_main!(CliArgs, IntegrationTestArgs, setup_integration_tests);