//! Integration tests for the handshake manager
use arbitrum_client::constants::Chain;
use clap::Parser;
use config::RelayerConfig;
use eyre::Result;
use libp2p::identity::Keypair;
use mock_node::MockNodeController;
use test_helpers::{
    arbitrum::{DEFAULT_DEVNET_HOSTPORT, DEFAULT_DEVNET_PKEY},
    integration_test, integration_test_main,
    types::TestVerbosity,
};
use tracing::level_filters::LevelFilter;
use util::arbitrum::{parse_addr_from_deployments_file, DARKPOOL_PROXY_CONTRACT_KEY};

/// A mock execution price to use in the integration tests
const MOCK_EXECUTION_PRICE: f64 = 0.154;

// -------
// | CLI |
// -------

/// The arguments for the integration tests
#[derive(Debug, Clone, Parser)]
struct CliArgs {
    // --- Network Config --- //
    /// The local peer's base64 encoded p2p key
    #[arg(long)]
    my_key: String,
    /// The port that the local peer listens on
    #[arg(long)]
    my_port: u16,
    /// The remote peer's base64 encoded p2p key
    ///
    /// We use this only to recover a peer's ID
    #[arg(long)]
    peer_key: String,
    /// The port that the remote peer listens on
    #[arg(long)]
    peer_port: u16,

    // --- Chain Config --- //
    /// The private key to use for the Arbitrum account during testing
    ///
    /// Defaults to the first pre-deployed account on the `nitro-testnode`
    #[arg(
        short = 'p',
        long,
        default_value = DEFAULT_DEVNET_PKEY
    )]
    arbitrum_pkey: String,
    /// The location of a `deployments.json` file that contains the addresses of
    /// the deployed contracts
    #[arg(long)]
    deployments_path: String,
    /// The url the devnet node api server
    #[arg(long, default_value = DEFAULT_DEVNET_HOSTPORT)]
    devnet_url: String,

    // --- Harness Config --- //
    /// The test to run
    #[arg(short, long, value_parser)]
    test: Option<String>,
    /// The verbosity level of the test harness
    #[arg(long, short, default_value = "default")]
    verbosity: TestVerbosity,
}

/// The arguments passed to every integration test
#[derive(Clone)]
struct IntegrationTestArgs {
    /// The handshake manager's queue
    mock_node: MockNodeController,
}

impl From<CliArgs> for IntegrationTestArgs {
    fn from(args: CliArgs) -> Self {
        // Setup the relayer config
        let p2p_key = parse_keypair(&args.my_key);
        let contract_address =
            parse_addr_from_deployments_file(&args.deployments_path, DARKPOOL_PROXY_CONTRACT_KEY)
                .unwrap();

        let conf = RelayerConfig {
            p2p_key,
            p2p_port: args.my_port,
            chain_id: Chain::Devnet,
            arbitrum_private_key: args.arbitrum_pkey,
            contract_address,
            rpc_url: Some(args.devnet_url),
            ..Default::default()
        };

        // Setup a mock node
        let mock_node = MockNodeController::new(conf)
            .with_state()
            .with_arbitrum_client()
            .with_mock_price_reporter(MOCK_EXECUTION_PRICE)
            .with_handshake_manager()
            .with_network_manager()
            .with_task_driver();

        Self { mock_node }
    }
}

/// Parse a keypair from a base64 encoded string
fn parse_keypair(encoded: &str) -> Keypair {
    let bytes = base64::decode(encoded).unwrap();
    Keypair::from_protobuf_encoding(&bytes).unwrap()
}

// ----------------
// | Test Harness |
// ----------------

/// Setup code for the integration tests
fn setup_integration_tests(test_args: &CliArgs) {
    // Configure the logging
    if matches!(test_args.verbosity, TestVerbosity::Full) {
        util::logging::setup_system_logger(LevelFilter::INFO);
    }
}

integration_test_main!(CliArgs, IntegrationTestArgs, setup_integration_tests);

/// A dummy test
fn dummy_test(args: IntegrationTestArgs) -> Result<()> {
    let state = args.mock_node.state();
    let local_peer_id = state.get_peer_id().unwrap();
    println!("local peer id: {local_peer_id:?}");

    Ok(())
}

integration_test!(dummy_test);
