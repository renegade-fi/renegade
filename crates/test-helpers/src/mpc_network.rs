//! Groups helpers for setting up and managing an MPC network
pub mod mock_with_delay;
pub mod mocks;

use std::{fmt::Debug, net::SocketAddr, sync::Arc, time::Duration};

use ark_mpc::{
    ExecutorSizeHints, MpcFabric, PARTY0, PARTY1,
    network::{MpcNetwork, QuicTwoPartyNet},
};
use constants::SystemCurveGroup;
use dns_lookup::lookup_host;
use futures::{Future, executor::block_on, future::join_all};
use tokio::runtime::Handle;

use crate::mpc_network::mocks::MockNetwork;

use self::{
    mock_with_delay::MockNetworkWithDelay,
    mocks::{PartyIDBeaverSource, UnboundedDuplexStream},
};

/// The size of MPC network to allocate by default
pub const DEFAULT_MPC_SIZE_HINT: ExecutorSizeHints =
    ExecutorSizeHints { n_ops: 1_000, n_results: 1_000_000 };

// -----------
// | Helpers |
// -----------

/// Sets up a basic MPC fabric between two parties using the QUIC transport and
/// the beaver triplet source defined above
pub fn setup_mpc_fabric(
    party_id: u64,
    local_port: u64,
    peer_port: u64,
    docker: bool,
) -> MpcFabric<SystemCurveGroup> {
    // Listen on 0.0.0.0 (all network interfaces) with the given port
    // We do this because listening on localhost when running in a container points
    // to the container's loopback interface, not the docker bridge
    let local_addr: SocketAddr = format!("0.0.0.0:{}", local_port).parse().unwrap();

    // If the code is running in a docker compose setup (set by the --docker flag);
    // attempt to lookup the peer via DNS. The compose networking interface will
    // add an alias for party0 for the first peer and party1 for the second.
    // If not running on docker, dial the peer directly on the loopback interface.
    let peer_addr: SocketAddr = {
        if docker {
            let other_host_alias = format!("party{}", if party_id == 1 { 0 } else { 1 });
            let hosts = lookup_host(other_host_alias.as_str()).unwrap();

            println!("Lookup successful for {}... found hosts: {:?}", other_host_alias, hosts);

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
pub async fn execute_mock_mpc<T, S, F>(f: F) -> (T, T)
where
    T: Send + 'static,
    S: Future<Output = T> + Send + 'static,
    F: Fn(MpcFabric<SystemCurveGroup>) -> S + Send + Sync + 'static,
{
    // Build a duplex stream to broker communication between the two parties
    let (party0_stream, party1_stream) = UnboundedDuplexStream::new_duplex_pair();
    let party0_conn = MockNetwork::new(PARTY0, party0_stream);
    let party1_conn = MockNetwork::new(PARTY1, party1_stream);

    execute_mock_mpc_with_network_and_hint(
        f,
        party0_conn,
        party1_conn,
        ExecutorSizeHints::default(),
    )
    .await
}

/// Run a mock MPC connected by a duplex stream that has an added delay as the
/// mock network
pub async fn execute_mock_mpc_with_delay<T, S, F>(f: F, delay: Duration) -> (T, T)
where
    T: Send + 'static,
    S: Future<Output = T> + Send + 'static,
    F: Fn(MpcFabric<SystemCurveGroup>) -> S + Send + Sync + 'static,
{
    // Build a duplex stream to broker communication between the two parties
    execute_mock_mpc_with_delay_and_hint(f, delay, ExecutorSizeHints::default()).await
}

/// Execute a mock MPC connected by a duplex stream as the mock network. Use the
/// provided size hint when constructing the fabric
pub async fn execute_mock_mpc_with_delay_and_hint<T, S, F>(
    f: F,
    delay: Duration,
    hint: ExecutorSizeHints,
) -> (T, T)
where
    T: Send + 'static,
    S: Future<Output = T> + Send + 'static,
    F: Fn(MpcFabric<SystemCurveGroup>) -> S + Send + Sync + 'static,
{
    let (party0_stream, party1_stream) = UnboundedDuplexStream::new_duplex_pair();
    let party0_conn = MockNetworkWithDelay::new(PARTY0, party0_stream, delay);
    let party1_conn = MockNetworkWithDelay::new(PARTY1, party1_stream, delay);

    execute_mock_mpc_with_network_and_hint(f, party0_conn, party1_conn, hint).await
}

/// Execute a mock MPC with a given implementation of `MpcNetwork`
async fn execute_mock_mpc_with_network_and_hint<T, S, F, N>(
    f: F,
    party0_conn: N,
    party1_conn: N,
    hint: ExecutorSizeHints,
) -> (T, T)
where
    T: Send + 'static,
    S: Future<Output = T> + Send + 'static,
    F: Fn(MpcFabric<SystemCurveGroup>) -> S + Send + Sync + 'static,
    N: MpcNetwork<SystemCurveGroup> + Send + Sync + 'static,
{
    // Build a duplex stream to broker communication between the two parties
    let party0_fabric =
        MpcFabric::new_with_size_hint(hint, party0_conn, PartyIDBeaverSource::new(PARTY0));
    let party1_fabric =
        MpcFabric::new_with_size_hint(hint, party1_conn, PartyIDBeaverSource::new(PARTY1));

    // Spawn two tasks to execute the MPC
    let fabric0 = party0_fabric.clone();
    let fabric1 = party1_fabric.clone();

    // Move the function pointer to the heap and pass shared ownership to both tasks
    let arc_f = Arc::new(f);
    let f_clone1 = arc_f.clone();
    let f_clone2 = arc_f.clone();

    let party0_task =
        tokio::task::spawn_blocking(move || Handle::current().block_on(f_clone1(fabric0)));
    let party1_task =
        tokio::task::spawn_blocking(move || Handle::current().block_on(f_clone2(fabric1)));

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
    Handle::current().block_on(f).map_err(|e| format!("error awaiting result: {e:?}"))
}

/// Await a batch of results in a fabric, blocking the current thread
pub fn await_result_batch<F, T>(f: Vec<F>) -> Vec<T>
where
    F: Future<Output = T>,
{
    Handle::current().block_on(futures::future::join_all(f))
}

/// Await a batch of results that may error returning a string in place
pub fn await_result_batch_with_error<F, T, E>(f: Vec<F>) -> Result<Vec<T>, String>
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
