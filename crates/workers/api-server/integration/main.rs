//! Integration tests for the api-server crate
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![allow(incomplete_features)]

use circuit_types::fixed_point::FixedPoint;
use clap::Parser;
use config::RelayerConfig;
use mock_node::MockNodeController;
use state::test_helpers::tmp_db_path;
use test_helpers::{integration_test, integration_test_main, types::TestVerbosity};
use types_core::{Token, get_all_tokens};
use util::{
    on_chain::{set_default_protocol_fee, set_protocol_fee_for_pair},
    telemetry::LevelFilter,
};

// -------
// | CLI |
// -------

/// The arguments used to run the integration tests
#[derive(Debug, Clone, Parser)]
#[command(author, version, about, long_about=None)]
struct CliArgs {
    /// The test to run
    #[arg(short, long, value_parser)]
    test: Option<String>,
    /// The verbosity level of the test harness
    #[arg(long, short, default_value = "default")]
    verbosity: TestVerbosity,
}

/// A dummy RPC url for the integration tests
const DUMMY_RPC_URL: &str = "https://dummy-rpc-url.com";

/// The arguments provided to every integration test
#[derive(Clone)]
pub struct IntegrationTestArgs {
    /// The mock node controller
    pub mock_node: MockNodeController,
    /// The verbosity level
    pub verbosity: TestVerbosity,
}

// -----------
// | Mocking |
// -----------

impl IntegrationTestArgs {
    /// Get the relayer config for the integration tests
    fn relayer_config() -> RelayerConfig {
        let raft_snapshot_path = tmp_db_path();
        let db_path = tmp_db_path();

        RelayerConfig {
            raft_snapshot_path,
            db_path,
            rpc_url: Some(DUMMY_RPC_URL.to_string()),
            ..Default::default()
        }
    }
}

impl From<CliArgs> for IntegrationTestArgs {
    fn from(args: CliArgs) -> Self {
        let cfg = Self::relayer_config();
        let mock_node = MockNodeController::new(cfg)
            .with_darkpool_client()
            .with_state()
            .with_matching_engine_manager()
            .with_mock_price_reporter(0.0001 /* price */)
            .with_task_driver()
            .with_mock_proof_generation(true /* skip_constraints */)
            .with_api_server();

        Self { mock_node, verbosity: args.verbosity }
    }
}

// ----------------
// | Test Harness |
// ----------------

/// Setup code for the integration tests
fn setup_integration_tests(test_args: &IntegrationTestArgs) {
    // Set the default and per-pair protocol fees
    let fee = FixedPoint::from_f64_round_down(0.0001);
    set_default_protocol_fee(fee);
    let usdc = Token::usdc().get_alloy_address();
    for token in get_all_tokens() {
        let addr = token.get_alloy_address();
        set_protocol_fee_for_pair(&addr, &usdc, fee);
    }

    // Configure logging
    if matches!(test_args.verbosity, TestVerbosity::Full) {
        util::telemetry::setup_system_logger(LevelFilter::INFO);
    }
}

integration_test_main!(CliArgs, IntegrationTestArgs, setup_integration_tests);

// ---------
// | Tests |
// ---------

/// A dummy test that does nothing
fn test_dummy(_args: IntegrationTestArgs) {
    // This is a placeholder test
}
integration_test!(test_dummy);
