#![cfg(test)]
mod mpc_circuits;
mod mpc_gadgets;
mod zk_circuits;
mod zk_gadgets;

use std::cell::Ref;

use circuits::mpc::{MpcFabric, SharedFabric};
use clap::Parser;
use integration_helpers::{
    integration_test_main,
    mpc_network::{mocks::PartyIDBeaverSource, setup_mpc_fabric},
};
use mpc_ristretto::network::QuicTwoPartyNet;

/// A type alias for a shared mutability wrapper around the MPC fabric
type SharedMpcFabric = SharedFabric<QuicTwoPartyNet, PartyIDBeaverSource>;

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
    pub(crate) mpc_fabric: SharedMpcFabric,
    pub(crate) party_id: u64,
}

impl IntegrationTestArgs {
    pub(crate) fn borrow_fabric(&self) -> Ref<MpcFabric<QuicTwoPartyNet, PartyIDBeaverSource>> {
        self.mpc_fabric.borrow_fabric()
    }
}

impl From<CliArgs> for IntegrationTestArgs {
    fn from(args: CliArgs) -> Self {
        let mpc_fabric = SharedFabric(setup_mpc_fabric(
            args.party,
            args.port1,
            args.port2,
            args.docker,
        ));
        let party_id = mpc_fabric.borrow_fabric().party_id();

        Self {
            mpc_fabric,
            party_id,
        }
    }
}

integration_test_main!(CliArgs, IntegrationTestArgs);
