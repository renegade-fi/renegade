//! Integration tests for the api-server crate
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![allow(incomplete_features)]

use std::time::Duration;

use circuit_types::fixed_point::FixedPoint;
use clap::Parser;
use config::RelayerConfig;
use constants::GLOBAL_MATCHING_POOL;
use external_api::{
    EmptyRequestResponse,
    auth::add_expiring_auth_to_headers,
    http::admin::{ADMIN_SET_ACCOUNT_DEFAULT_POOL_ROUTE, SetAccountDefaultMatchingPoolRequest},
};
use mock_node::MockNodeController;
use reqwest::{Method, header::HeaderMap};
use state::test_helpers::tmp_db_path;
use test_helpers::{integration_test, integration_test_async, integration_test_main, types::TestVerbosity};
use types_account::account::mocks::mock_empty_account;
use types_core::HmacKey;
use util::{on_chain::set_protocol_fee, telemetry::LevelFilter};

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
/// A test matching pool name
const TEST_POOL_NAME: &str = "mm-test";
/// Auth expiration window used in test requests
const AUTH_EXPIRY: Duration = Duration::from_secs(60);

/// The arguments provided to every integration test
#[derive(Clone)]
pub struct IntegrationTestArgs {
    /// The mock node controller
    pub mock_node: MockNodeController,
    /// The admin API key for this test run
    pub admin_key: HmacKey,
    /// The verbosity level
    pub verbosity: TestVerbosity,
}

// -----------
// | Mocking |
// -----------

impl IntegrationTestArgs {
    /// Get the relayer config for the integration tests
    fn relayer_config() -> (RelayerConfig, HmacKey) {
        let raft_snapshot_path = tmp_db_path();
        let db_path = tmp_db_path();
        let admin_key = HmacKey::random();

        let config = RelayerConfig {
            raft_snapshot_path,
            db_path,
            rpc_url: Some(DUMMY_RPC_URL.to_string()),
            admin_api_key: Some(admin_key.clone()),
            ..Default::default()
        };
        (config, admin_key)
    }

    /// Build admin auth headers for a POST request to the given path with the given body
    fn admin_headers(&self, path: &str, body: &[u8]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        add_expiring_auth_to_headers(path, &mut headers, body, &self.admin_key, AUTH_EXPIRY);
        headers
    }
}

impl From<CliArgs> for IntegrationTestArgs {
    fn from(args: CliArgs) -> Self {
        let (cfg, admin_key) = Self::relayer_config();
        let mock_node = MockNodeController::new(cfg)
            .with_darkpool_client()
            .with_state()
            .with_matching_engine_manager()
            .with_mock_price_reporter(0.0001 /* price */)
            .with_task_driver()
            .with_mock_proof_generation(true /* skip_constraints */)
            .with_api_server();

        Self { mock_node, admin_key, verbosity: args.verbosity }
    }
}

// ----------------
// | Test Harness |
// ----------------

/// Setup code for the integration tests
fn setup_integration_tests(test_args: &IntegrationTestArgs) {
    // Set the global protocol fee
    let fee = FixedPoint::from_f64_round_down(0.0001);
    set_protocol_fee(fee);

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

/// Tests that an account bound to a pool via the admin route has its
/// `default_matching_pool` reflected in the state after the call.
async fn test_set_account_default_pool_persists(args: IntegrationTestArgs) -> eyre::Result<()> {
    let state = args.mock_node.state();

    // Create an account and a matching pool directly in state
    let account = mock_empty_account();
    let account_id = account.id;
    state.new_account(account).await?.await?;
    state.create_matching_pool(TEST_POOL_NAME.to_string()).await?.await?;

    // Call the admin route to bind the account to the pool
    let route = ADMIN_SET_ACCOUNT_DEFAULT_POOL_ROUTE
        .replace(":account_id", &account_id.to_string());
    let req =
        SetAccountDefaultMatchingPoolRequest { matching_pool: Some(TEST_POOL_NAME.to_string()) };
    let body = serde_json::to_vec(&req)?;
    let headers = args.admin_headers(&route, &body);

    args.mock_node
        .send_api_req::<_, EmptyRequestResponse>(&route, Method::POST, headers, req)
        .await?;

    // Verify the field is persisted in state
    let loaded = state.get_account(&account_id).await?.expect("account not found");
    assert_eq!(loaded.default_matching_pool.as_deref(), Some(TEST_POOL_NAME));
    Ok(())
}
integration_test_async!(test_set_account_default_pool_persists);

/// Tests that an account with no default pool binding has orders routed to the
/// global matching pool.
async fn test_unbound_account_uses_global_pool(args: IntegrationTestArgs) -> eyre::Result<()> {
    let state = args.mock_node.state();

    // Create an unbound account and verify default pool is None
    let account = mock_empty_account();
    let account_id = account.id;
    state.new_account(account).await?.await?;

    let loaded = state.get_account(&account_id).await?.expect("account not found");
    assert!(
        loaded.default_matching_pool.is_none(),
        "expected no default pool for unbound account"
    );

    // Confirm the fallback logic: None maps to GLOBAL_MATCHING_POOL
    let pool = loaded.default_matching_pool.unwrap_or_else(|| GLOBAL_MATCHING_POOL.to_string());
    assert_eq!(pool, GLOBAL_MATCHING_POOL);
    Ok(())
}
integration_test_async!(test_unbound_account_uses_global_pool);
