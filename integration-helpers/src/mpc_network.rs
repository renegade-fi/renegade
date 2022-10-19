//! Groups helpers for setting up and managing an MPC network

use std::{cell::RefCell, net::SocketAddr, rc::Rc};

use curve25519_dalek::scalar::Scalar;
use dns_lookup::lookup_host;
use mpc_ristretto::{
    beaver::SharedValueSource, fabric::AuthenticatedMpcFabric, network::QuicTwoPartyNet,
};

/**
 * Helper Structs
 */

/// An implementation of a beaver value source that returns
/// beaver triples (0, 0, 0) for party 0 and (1, 1, 1) for party 1
#[derive(Debug)]
pub struct PartyIDBeaverSource {
    party_id: u64,
}

impl PartyIDBeaverSource {
    pub fn new(party_id: u64) -> Self {
        Self { party_id }
    }
}

/// The PartyIDBeaverSource returns beaver triplets split statically between the
/// parties. We assume a = 2, b = 3 ==> c = 6. [a] = (1, 1); [b] = (3, 0) [c] = (2, 4)
impl SharedValueSource<Scalar> for PartyIDBeaverSource {
    fn next_shared_bit(&mut self) -> Scalar {
        // Simply output partyID, assume partyID \in {0, 1}
        assert!(self.party_id == 0 || self.party_id == 1);
        Scalar::from(self.party_id as u64)
    }

    fn next_triplet(&mut self) -> (Scalar, Scalar, Scalar) {
        if self.party_id == 0 {
            (Scalar::from(1u64), Scalar::from(3u64), Scalar::from(2u64))
        } else {
            (Scalar::from(1u64), Scalar::from(0u64), Scalar::from(4u64))
        }
    }

    fn next_shared_value(&mut self) -> Scalar {
        Scalar::from(self.party_id)
    }
}

/// Sets up a basic MPC fabric between two parties using the QUIC transport and
/// the beaver triplet source defined above
pub async fn setup_mpc_fabric(
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

    net.connect().await.unwrap();

    // Share the global mac key (hardcoded to Scalar(15))
    let net_ref = Rc::new(RefCell::new(net));
    let beaver_source = Rc::new(RefCell::new(PartyIDBeaverSource::new(party_id)));

    Rc::new(RefCell::new(AuthenticatedMpcFabric::new_with_network(
        party_id,
        net_ref,
        beaver_source,
    )))
}
