//! Integration tests for the handshake manager
use clap::Parser;
use job_types::handshake_manager::HandshakeManagerQueue;
use test_helpers::{
    arbitrum::{DEFAULT_DEVNET_HOSTPORT, DEFAULT_DEVNET_PKEY},
    integration_test_main,
    types::TestVerbosity,
};
use tracing::level_filters::LevelFilter;

// -------
// | CLI |
// -------

/// The arguments for the integration tests
#[derive(Debug, Clone, Parser)]
struct CliArgs {
    // --- Network Config --- //
    /// The local peer's Peer ID
    #[arg(long)]
    my_addr: String,
    /// The multiaddr of the other peer
    #[arg(long)]
    peer_addr: String,

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
    handshake_queue: HandshakeManagerQueue,
}

impl From<CliArgs> for IntegrationTestArgs {
    fn from(value: CliArgs) -> Self {
        println!("Creating handshake manager queue");
        todo!()
    }
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
