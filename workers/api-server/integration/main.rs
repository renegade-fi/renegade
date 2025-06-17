//! Integration tests for the `api-server` crate

use api_server::http::PING_ROUTE;
use clap::Parser;
use common::types::{chain::Chain, hmac::HmacKey};
use config::setup_token_remaps;
use external_api::{http::PingResponse, EmptyRequestResponse};
use eyre::Result;
use mock_node::MockNodeController;
use rand::{distributions::uniform::SampleRange, thread_rng};
use reqwest::Method;
use test_helpers::{
    assert_true_result, integration_test_async, integration_test_main, types::TestVerbosity,
};

use crate::ctx::IntegrationTestCtx;

mod ctx;
mod external_match;
mod to_eyre;

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

// ---------
// | Setup |
// ---------

impl From<CliArgs> for IntegrationTestCtx {
    fn from(_args: CliArgs) -> Self {
        // Use the Arbitrum Sepolia token remap for testing
        setup_token_remaps(None /* remap_file */, Chain::ArbitrumSepolia)
            .expect("failed to setup token remaps");

        // Sample a mock price
        let mut rng = thread_rng();
        let mock_price = (0.0001..1000.).sample_single(&mut rng);

        let admin_api_key = HmacKey::random();
        let cfg = Self::relayer_config(admin_api_key);
        let mock_node = MockNodeController::new(cfg)
            .with_darkpool_client()
            .with_state()
            .with_handshake_manager()
            .with_mock_price_reporter(mock_price)
            .with_api_server();

        Self { admin_api_key, mock_node }
    }
}

integration_test_main!(CliArgs, IntegrationTestCtx);

// ---------
// | Tests |
// ---------

/// Tests that the api server can be pinged
async fn test_ping(ctx: IntegrationTestCtx) -> Result<()> {
    let resp: PingResponse = ctx.send_req(PING_ROUTE, Method::GET, EmptyRequestResponse {}).await?;
    assert_true_result!(resp.timestamp > 0)
}
integration_test_async!(test_ping);
