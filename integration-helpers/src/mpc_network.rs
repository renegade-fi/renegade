//! Groups helpers for setting up and managing an MPC network
pub mod field;
pub mod mocks;

use std::{cell::RefCell, net::SocketAddr, rc::Rc};

use curve25519_dalek::scalar::Scalar;
use dns_lookup::lookup_host;
use futures::executor::block_on;
use mpc_ristretto::{
    authenticated_scalar::AuthenticatedScalar,
    beaver::SharedValueSource,
    fabric::AuthenticatedMpcFabric,
    network::{MpcNetwork, QuicTwoPartyNet},
};

use self::mocks::{MockMpcNet, PartyIDBeaverSource};

/**
 * Types
 */
#[allow(type_alias_bounds)]
pub type SharedFabric<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> =
    Rc<RefCell<AuthenticatedMpcFabric<N, S>>>;

/**
 * Helpers
 */

/// Helper to share a plaintext value with the peer over a fabric
///
/// This method is inefficient, but practical for tests
pub fn share_plaintext_scalar<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    value: Scalar,
    owning_party: u64,
    fabric: SharedFabric<N, S>,
) -> Scalar {
    fabric
        .as_ref()
        .borrow()
        .allocate_private_scalar(owning_party, value)
        .unwrap()
        .open()
        .unwrap()
        .to_scalar()
}

/// Helper to share a batch of plaintext values with the peer over a fabric
///
/// As above, this method is relatively inefficient, but okay for tests
pub fn batch_share_plaintext_scalar<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    values: &[Scalar],
    owning_party: u64,
    fabric: SharedFabric<N, S>,
) -> Vec<Scalar> {
    let shared_values = fabric
        .as_ref()
        .borrow()
        .batch_allocate_private_scalars(owning_party, values)
        .unwrap();

    AuthenticatedScalar::batch_open(&shared_values)
        .unwrap()
        .iter()
        .map(|val| val.to_scalar())
        .collect::<Vec<_>>()
}

/// Mocks out an MPC fabric, unlike the method below, no actual communication channel is
/// created. The method below returns a fabric to be used in integration tests.
pub fn mock_mpc_fabric(party_id: u64) -> SharedFabric<MockMpcNet, PartyIDBeaverSource> {
    Rc::new(RefCell::new(AuthenticatedMpcFabric::new_with_network(
        party_id,
        Rc::new(RefCell::new(MockMpcNet::default())),
        Rc::new(RefCell::new(PartyIDBeaverSource::new(party_id))),
    )))
}

/// Sets up a basic MPC fabric between two parties using the QUIC transport and
/// the beaver triplet source defined above
pub fn setup_mpc_fabric(
    party_id: u64,
    local_port: u64,
    peer_port: u64,
    docker: bool,
) -> Rc<RefCell<AuthenticatedMpcFabric<QuicTwoPartyNet, PartyIDBeaverSource>>> {
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

    // Share the global mac key (hardcoded to Scalar(15))
    let net_ref = Rc::new(RefCell::new(net));
    let beaver_source = Rc::new(RefCell::new(PartyIDBeaverSource::new(party_id)));

    Rc::new(RefCell::new(AuthenticatedMpcFabric::new_with_network(
        party_id,
        net_ref,
        beaver_source,
    )))
}
