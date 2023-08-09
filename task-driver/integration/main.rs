//! Defines integration tests for
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

use clap::Parser;
use common::types::chain_id::ChainId;
use starknet_client::client::{StarknetClient, StarknetClientConfig};
use test_helpers::integration_test_main;
use tracing::log::LevelFilter;
use util::runtime::await_result;

/// The hostport that the test expects a local devnet node to be running on
///
/// This assumes that the integration tests are running in a docker-compose setup
/// with a DNS alias `sequencer` pointing to a devnet node running in a sister container
const DEVNET_HOSTPORT: &str = "http://sequencer:5050/rpc";

/// The arguments used to run the integration tests
#[derive(Debug, Clone, Parser)]
#[command(author, version, about, long_about=None)]
struct CliArgs {
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
}

impl From<CliArgs> for IntegrationTestArgs {
    fn from(_: CliArgs) -> Self {
        let starknet_client = StarknetClient::new(StarknetClientConfig {
            chain: ChainId::Devnet,
            contract_addr: "".to_string(),
            // Assumes we are running in a docker-compose setup with a DNS alias `sequencer`
            // pointing to a devnet node running in a sister container
            starknet_json_rpc_addr: Some(DEVNET_HOSTPORT.to_string()),
            infura_api_key: None,
            starknet_account_addresses: vec![],
            starknet_pkeys: vec![],
        });

        Self { starknet_client }
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
fn test_dummy(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let client = &test_args.starknet_client;
    let block_num = await_result(client.get_block_number())
        .map_err(|e| format!("error fetching block number: {e}"))?;

    if block_num == 0 {
        Ok(())
    } else {
        Err(format!("expected block number to be 0, got {block_num}"))
    }
}

inventory::submit!(TestWrapper(IntegrationTest {
    name: "dummy",
    test_fn: test_dummy,
}));

integration_test_main!(CliArgs, IntegrationTestArgs, setup_integration_tests);
