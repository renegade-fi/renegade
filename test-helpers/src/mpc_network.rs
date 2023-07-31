//! Groups helpers for setting up and managing an MPC network
pub mod field;
pub mod mocks;

use std::{fmt::Debug, net::SocketAddr};

use dns_lookup::lookup_host;
use futures::{executor::block_on, future::join_all, Future};
use mpc_stark::{network::QuicTwoPartyNet, MpcFabric, PARTY0, PARTY1};
use tokio::runtime::Handle;

use crate::mpc_network::mocks::MockNetwork;

use self::mocks::{PartyIDBeaverSource, UnboundedDuplexStream};

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

/// Run a mock MPC connected by a duplex stream as the mock network
///
/// This will spawn two tasks to execute either side of the MPC
///
/// Returns the outputs of both parties
pub async fn execute_mock_mpc<T, S, F>(mut f: F) -> (T, T)
where
    T: Send + 'static,
    S: Future<Output = T> + Send + 'static,
    F: FnMut(MpcFabric) -> S,
{
    // Build a duplex stream to broker communication between the two parties
    let (party0_stream, party1_stream) = UnboundedDuplexStream::new_duplex_pair();
    let party0_fabric = MpcFabric::new(
        MockNetwork::new(PARTY0, party0_stream),
        PartyIDBeaverSource::new(PARTY0),
    );
    let party1_fabric = MpcFabric::new(
        MockNetwork::new(PARTY1, party1_stream),
        PartyIDBeaverSource::new(PARTY1),
    );

    // Spawn two tasks to execute the MPC
    let fabric0 = party0_fabric.clone();
    let fabric1 = party1_fabric.clone();
    let party0_task = tokio::spawn(f(fabric0));
    let party1_task = tokio::spawn(f(fabric1));

    let party0_output = party0_task.await.unwrap();
    let party1_output = party1_task.await.unwrap();

    // Shutdown the fabrics
    party0_fabric.shutdown();
    party1_fabric.shutdown();

    (party0_output, party1_output)
}

/// Await a result in a fabric, blocking the current thread
pub fn await_result<F, T>(f: F) -> T
where
    F: Future<Output = T>,
{
    Handle::current().block_on(f)
}

/// Await a result in the fabric that may error, returning a string in place
pub fn await_result_with_error<F, T, E>(f: F) -> Result<T, String>
where
    F: Future<Output = Result<T, E>>,
    E: Debug,
{
    Handle::current()
        .block_on(f)
        .map_err(|e| format!("error awaiting result: {e:?}"))
}

/// Await a batch of results in a fabric, blocking the current thread
pub fn await_result_batch<F, T>(f: &[F]) -> Vec<T>
where
    F: Future<Output = T>,
{
    Handle::current().block_on(futures::future::join_all(f))
}

/// Await a batch of results that may error returning a string in place
pub fn await_result_batch_with_error<F, T, E>(f: &[F]) -> Result<Vec<T>, String>
where
    F: Future<Output = Result<T, E>>,
    E: Debug,
{
    Handle::current()
        .block_on(join_all(f))
        .into_iter()
        .collect::<Result<Vec<T>, E>>()
        .map_err(|e| format!("error awaiting result: {e:?}"))
}
