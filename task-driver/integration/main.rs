//! Defines integration tests for
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

use clap::Parser;
use test_helpers::integration_test_main;
use tracing::log::LevelFilter;

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
#[derive(Debug, Clone)]
struct IntegrationTestArgs;
impl From<CliArgs> for IntegrationTestArgs {
    fn from(_: CliArgs) -> Self {
        Self
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
fn test_dummy(_test_args: &IntegrationTestArgs) -> Result<(), String> {
    println!("got here!");
    Ok(())
}

inventory::submit!(TestWrapper(IntegrationTest {
    name: "dummy",
    test_fn: test_dummy,
}));

integration_test_main!(CliArgs, IntegrationTestArgs, setup_integration_tests);
