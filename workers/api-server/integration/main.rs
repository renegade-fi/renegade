//! Integration tests for the `api-server` crate

use std::env::temp_dir;

use api_server::http::PING_ROUTE;
use clap::Parser;
use common::types::chain::Chain;
use config::{setup_token_remaps, RelayerConfig};
use external_api::{http::PingResponse, EmptyRequestResponse};
use eyre::Result;
use hyper::Method;
use mock_node::MockNodeController;
use state::test_helpers::tmp_db_path;
use test_helpers::{
    assert_true_result, integration_test_async, integration_test_main, types::TestVerbosity,
};

// -------------
// | Arguments |
// -------------

/// The arguments used for running api-server integration tests
#[derive(Debug, Clone, Parser)]
#[command(author, version, about, long_about=None)]
struct CliArgs {
    /// The test to run
    #[arg(short, long, value_parser)]
    test: Option<String>,
    /// Whether or not to print output during the course of the tests
    #[arg(long, default_value = "default")]
    verbosity: TestVerbosity,
}

/// The arguments used for the integration tests
#[derive(Clone)]
struct IntegrationTestArgs {
    /// The mock node controller
    mock_node: MockNodeController,
}

impl IntegrationTestArgs {
    /// Get the relayer config for the integration tests
    pub fn relayer_config() -> RelayerConfig {
        let raft_snapshot_path = temp_dir().to_str().unwrap().to_string();
        let db_path = tmp_db_path();
        RelayerConfig { raft_snapshot_path, db_path, ..Default::default() }
    }
}

// ---------
// | Setup |
// ---------

impl From<CliArgs> for IntegrationTestArgs {
    fn from(_args: CliArgs) -> Self {
        // Use the Arbitrum Sepolia token remap for testing
        setup_token_remaps(None /* remap_file */, Chain::ArbitrumSepolia)
            .expect("failed to setup token remaps");

        let cfg = Self::relayer_config();
        let mock_node =
            MockNodeController::new(cfg).with_darkpool_client().with_state().with_api_server();

        Self { mock_node }
    }
}

integration_test_main!(CliArgs, IntegrationTestArgs);

// ---------
// | Tests |
// ---------

/// Tests that the api server can be pinged
async fn test_ping(test_args: IntegrationTestArgs) -> Result<()> {
    let node = &test_args.mock_node;
    let resp: PingResponse =
        node.send_api_req(PING_ROUTE, Method::GET, EmptyRequestResponse {}).await?;

    assert_true_result!(resp.timestamp > 0)?;
    Ok(())
}
integration_test_async!(test_ping);
