#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

mod constants;
mod helpers;

use arbitrum_client::{
    client::{ArbitrumClient, ArbitrumClientConfig},
    constants::Chain,
};
use clap::Parser;
use constants::{DARKPOOL_CONTRACT_KEY, DARKPOOL_PROXY_CONTRACT_KEY};
use helpers::parse_addr_from_deployments_file;
use test_helpers::integration_test_main;
use util::{logging::LevelFilter, runtime::block_on_result};

use crate::constants::{DEFAULT_DEVNET_HOSTPORT, DEFAULT_DEVNET_PKEY};

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
        let event_source =
            parse_addr_from_deployments_file(&test_args.deployments_path, DARKPOOL_CONTRACT_KEY)
                .unwrap();

        // Build a client that references the darkpool
        // We block on the client creation so that we can match the (synchronous)
        // function signature of `From`, which is assumed to be implemented in
        // the integration test harness
        let client = block_on_result(ArbitrumClient::new(ArbitrumClientConfig {
            chain: Chain::Devnet,
            darkpool_addr,
            event_source,
            arb_priv_key: test_args.private_key,
            rpc_url: test_args.rpc_url,
        }))
        .unwrap();

        Self { client }
    }
}

/// Setup code for the integration tests
fn setup_integration_tests(_test_args: &CliArgs) {
    // Configure logging
    util::logging::setup_system_logger(LevelFilter::INFO);
}

integration_test_main!(CliArgs, IntegrationTestArgs, setup_integration_tests);
