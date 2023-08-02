#![cfg(test)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

// mod mpc_circuits;
mod mpc_gadgets;
mod types;
// mod zk_circuits;
// mod zk_gadgets;

use chrono::Local;
use clap::Parser;
use env_logger::Builder;
use mpc_stark::MpcFabric;
use test_helpers::{integration_test_main, mpc_network::setup_mpc_fabric};
use tracing::log::LevelFilter;

/// The arguments used for running circuits integration tests
#[derive(Debug, Clone, Parser)]
#[command(author, version, about, long_about=None)]
struct CliArgs {
    /// The party id of the local party
    #[arg(long, value_parser)]
    party: u64,
    /// The port to accept inbound on
    #[arg(long = "port1", value_parser)]
    port1: u64,
    /// The port to expect the counterparty on
    #[arg(long = "port2", value_parser)]
    port2: u64,
    /// The test to run
    #[arg(short, long, value_parser)]
    test: Option<String>,
    /// Whether running in docker or not, used for peer lookup
    #[arg(long)]
    docker: bool,
    /// Whether or not to print output during the course of the tests
    #[arg(long)]
    verbose: bool,
}

/// The arguments used for the integration tests
#[derive(Debug, Clone)]
struct IntegrationTestArgs {
    /// The MPC fabric to use during the course of the integration test
    pub(crate) mpc_fabric: MpcFabric,
}

impl From<CliArgs> for IntegrationTestArgs {
    fn from(args: CliArgs) -> Self {
        let mpc_fabric = setup_mpc_fabric(args.party, args.port1, args.port2, args.docker);

        Self { mpc_fabric }
    }
}

fn setup_integration_tests(_test_args: &CliArgs) {
    // Configure logging
    Builder::new()
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{}] - {}",
                Local::now().format("%Y-%m-%dT%H:%M:%S"),
                record.level(),
                record.args()
            )
        })
        .filter(None, LevelFilter::Info)
        .init();
}

integration_test_main!(CliArgs, IntegrationTestArgs, setup_integration_tests);
