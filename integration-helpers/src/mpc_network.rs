//! Groups helpers for setting up and managing an MPC network
pub mod field;
pub mod mocks;

use std::net::SocketAddr;

use dns_lookup::lookup_host;
use futures::executor::block_on;
use mpc_stark::{network::QuicTwoPartyNet, MpcFabric};

use self::mocks::PartyIDBeaverSource;

/// The size of MPC network to allocate by default
pub const DEFAULT_MPC_SIZE_HINT: usize = 1_000_000;

// -----------
// | Helpers |
// -----------

/// Sets up a basic MPC fabric between two parties using the QUIC transport and
/// the beaver triplet source defined above
pub fn setup_mpc_fabric(party_id: u64, local_port: u64, peer_port: u64, docker: bool) -> MpcFabric {
    // Listen on 0.0.0.0 (all network interfaces) with the given port
    // We do this because listening on localhost when running in a container points to
    // the container's loopback interface, not the docker bridge
    let local_addr: SocketAddr = format!("0.0.0.0:{}", local_port).parse().unwrap();

    // If the code is running in a docker compose setup (set by the --docker flag); attempt
    // to lookup the peer via DNS. The compose networking interface will add an alias for
    // party0 for the first peer and party1 for the second.
    // If not running on docker, dial the peer directly on the loopback interface.
    let peer_addr: SocketAddr = {
        if docker {
            let other_host_alias = format!("party{}", if party_id == 1 { 0 } else { 1 });
            let hosts = lookup_host(other_host_alias.as_str()).unwrap();

            println!(
                "Lookup successful for {}... found hosts: {:?}",
                other_host_alias, hosts
            );

            format!("{}:{}", hosts[0], peer_port).parse().unwrap()
        } else {
            format!("{}:{}", "127.0.0.1", peer_port).parse().unwrap()
        }
    };

    println!("Lookup successful, found peer at {:?}", peer_addr);

    // Build and connect to the network
    let mut net = QuicTwoPartyNet::new(party_id, local_addr, peer_addr);

    block_on(net.connect()).unwrap();

    let beaver_source = PartyIDBeaverSource::new(party_id);
    MpcFabric::new_with_size_hint(DEFAULT_MPC_SIZE_HINT, net, beaver_source)
}
